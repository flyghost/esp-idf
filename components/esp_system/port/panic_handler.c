// Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <stdlib.h>

#include "esp_spi_flash.h"

#include "esp_private/system_internal.h"

#include "soc/soc_memory_layout.h"
#include "soc/cpu.h"
#include "soc/soc_caps.h"
#include "soc/rtc.h"

#include "hal/soc_hal.h"
#include "hal/cpu_hal.h"

#include "sdkconfig.h"
#include "esp_rom_sys.h"

#if CONFIG_IDF_TARGET_ESP32
#include "esp32/dport_access.h"
#include "esp32/cache_err_int.h"
#elif CONFIG_IDF_TARGET_ESP32S2
#include "esp32s2/memprot.h"
#include "esp32s2/cache_err_int.h"
#elif CONFIG_IDF_TARGET_ESP32S3
#include "esp32s3/memprot.h"
#include "esp32s3/cache_err_int.h"
#endif

#include "esp_private/panic_internal.h"
#include "esp_private/panic_reason.h"

#include "hal/wdt_types.h"
#include "hal/wdt_hal.h"

extern int _invalid_pc_placeholder;

extern void esp_panic_handler(panic_info_t*);

static wdt_hal_context_t wdt0_context = {.inst = WDT_MWDT0, .mwdt_dev = &TIMERG0};

void *g_exc_frames[SOC_CPU_CORES_NUM] = {NULL};

/*
  Panic handlers; these get called when an unhandled exception occurs or the assembly-level
  task switching / interrupt code runs into an unrecoverable error. The default task stack
  overflow handler and abort handler are also in here.
*/

/*
  Note: The linker script will put everything in this file in IRAM/DRAM, so it also works with flash cache disabled.
*/
// 发生未处理的异常，或者程序的任务切换、终端代码遇到不可切换的任务时，将调用此函数
// 默认任务堆栈溢出处理程序和中止处理程序也位于此处
static void print_state_for_core(const void *f, int core)
{
    // 不是abort异常
    if (!g_panic_abort) {
        // 在串口打印一些寄存器的值
        panic_print_registers(f, core);
        panic_print_str("\r\n");
    }
    panic_print_backtrace(f, core);
}

static void print_state(const void *f)
{
    // 获取core id
#if !CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE
    int err_core = f == g_exc_frames[0] ? 0 : 1;
#else
    int err_core = 0;
#endif

    // 
    print_state_for_core(f, err_core);

    panic_print_str("\r\n");

#if !CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE
    // 如果有其他的frame信息，也打印出来
    for (int i = 0; i < SOC_CPU_CORES_NUM; i++) {
        // `f` is the frame for the offending core, see note above.
        if (err_core != i && g_exc_frames[i] != NULL) {
            print_state_for_core(g_exc_frames[i], i);
            panic_print_str("\r\n");
        }
    }
#endif
}

// 将架构异常框架转换为抽象的紧急信息
static void frame_to_panic_info(void *frame, panic_info_t *info, bool pseudo_excause)
{
    info->core = cpu_hal_get_core_id();         // 引发异常的核心
    info->exception = PANIC_EXCEPTION_FAULT;    // 引发异常的原因
    info->details = NULL;                       // 有关异常的更多信息
    info->reason = "Unknown";                   // 异常字符串
    info->pseudo_excause = pseudo_excause;      // 异常原因是否有特殊含义

    if (pseudo_excause) {
        panic_soc_fill_info(frame, info);
    } else {
        panic_arch_fill_info(frame, info);
    }

    info->state = print_state;
    info->frame = frame;
}

static void panic_handler(void *frame, bool pseudo_excause)
{
    // 获取正在执行代码的core id
    int core_id = cpu_hal_get_core_id();

    // 保存原始帧
    g_exc_frames[core_id] = frame;

    // 如果ESP开发板是双核CPU的话，有一定几率两个都进入panic，下面确保只有一个内核进入系统紧急处理程序
#if !CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE
    if (pseudo_excause) {
#define BUSY_WAIT_IF_TRUE(b)                { if (b) while(1); }
        // 看门狗到期,暂停non-offending核心，offending核心来处理panic
        BUSY_WAIT_IF_TRUE(panic_get_cause(frame) == PANIC_RSN_INTWDT_CPU0 && core_id == 1);
        BUSY_WAIT_IF_TRUE(panic_get_cause(frame) == PANIC_RSN_INTWDT_CPU1 && core_id == 0);

        // 如果发生缓存错误，暂停non-offending核心，offending核心来处理panic
        // 如果是cache error,但是当前的 core id 没有发生cache error，就不打印
        if (panic_get_cause(frame) == PANIC_RSN_CACHEERR && core_id != esp_cache_err_get_cpuid()) {
            // Only print the backtrace for the offending core in case of the cache error
            // 在缓存错误的情况下，只打印有问题的的内核回溯
            g_exc_frames[core_id] = NULL;
            while (1) {
                ;
            }
        }
    }

    esp_rom_delay_us(1);
    SOC_HAL_STALL_OTHER_CORES();
#endif // CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE

#if CONFIG_IDF_TARGET_ESP32
    // 设置cpu为idle
    esp_dport_access_int_abort();
#endif

#if !CONFIG_ESP_PANIC_HANDLER_IRAM
    // 重新使能IRAM
    if (!spi_flash_cache_enabled()) {
        spi_flash_enable_cache(core_id);
        panic_print_str("Re-enable cpu cache.\r\n");
    }
#endif

    // cpu处于ocd调试模式
    if (esp_cpu_in_ocd_debug_mode()) {
#if __XTENSA__
        if (!(esp_ptr_executable(cpu_ll_pc_to_ptr(panic_get_address(frame))) && (panic_get_address(frame) & 0xC0000000U))) {
            /* Xtensa ABI sets the 2 MSBs of the PC according to the windowed call size
             * Incase the PC is invalid, GDB will fail to translate addresses to function names
             * Hence replacing the PC to a placeholder address in case of invalid PC
             */
            panic_set_address(frame, (uint32_t)&_invalid_pc_placeholder);
        }
#endif
        // panic异常的原因是看门狗中断，则喂狗
        if (panic_get_cause(frame) == PANIC_RSN_INTWDT_CPU0 ||
            panic_get_cause(frame) == PANIC_RSN_INTWDT_CPU1) {
            wdt_hal_write_protect_disable(&wdt0_context);
            wdt_hal_handle_intr(&wdt0_context);
            wdt_hal_write_protect_enable(&wdt0_context);
        }
    }

    // 将frame转换为info结构
    panic_info_t info;
    frame_to_panic_info(frame, &info, pseudo_excause);

    // Call the system panic handler
    esp_panic_handler(&info);
}

void panicHandler(void *frame)
{
    // This panic handler gets called for when the double exception vector,
    // kernel exception vector gets used; as well as handling interrupt-based
    // faults cache error, wdt expiry. EXCAUSE register gets written with
    // one of PANIC_RSN_* values.
    // 双重异常向量、内核异常向量、基于中断的故障缓存错误、看门狗到期
    // gdb调试也会进入
    panic_handler(frame, true);
}

// 特殊异常处理函数
void xt_unhandled_exception(void *frame)
{
    panic_handler(frame, false);
}

void __attribute__((noreturn)) panic_restart(void)
{
    bool digital_reset_needed = false;
#ifdef CONFIG_IDF_TARGET_ESP32
    // On the ESP32, cache error status can only be cleared by system reset
    if (esp_cache_err_get_cpuid() != -1) {
        digital_reset_needed = true;
    }
#endif
#if CONFIG_IDF_TARGET_ESP32S2
    if (esp_memprot_is_intr_ena_any() || esp_memprot_is_locked_any()) {
        digital_reset_needed = true;
    }
#endif
    if (digital_reset_needed) {
        esp_restart_noos_dig();
    }
    esp_restart_noos();
}

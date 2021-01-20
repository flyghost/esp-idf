// Copyright 2015-2019 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "soc/uart_periph.h"
#include "soc/gpio_periph.h"
#include "esp_gdbstub_common.h"
#include "sdkconfig.h"

#define UART_NUM CONFIG_ESP_CONSOLE_UART_NUM

void esp_gdbstub_target_init(void)
{
}

int esp_gdbstub_getchar(void)
{
    // 死循环等待数据到来
    while (REG_GET_FIELD(UART_STATUS_REG(UART_NUM), UART_RXFIFO_CNT) == 0) {
        ;
    }

    // 读取串口数据
    return REG_READ(UART_FIFO_REG(UART_NUM));
}

void esp_gdbstub_putchar(int c)
{
    // 等待缓冲区有空余
    while (REG_GET_FIELD(UART_STATUS_REG(UART_NUM), UART_TXFIFO_CNT) >= 126) {
        ;
    }

    // 写入数据
    REG_WRITE(UART_FIFO_REG(UART_NUM), c);
}

// 读取一个地址里的值
int esp_gdbstub_readmem(intptr_t addr)
{
    // 判断传参的地址是否在无效内存区域
    if (addr < 0x20000000 || addr >= 0x80000000) {
        /* see esp_cpu_configure_region_protection */
        return -1;
    }

    // 地址4字节对齐后再取值
    uint32_t val_aligned = *(uint32_t *)(addr & (~3));

    // 小端：低位在低地址，高位在高地址，对齐后读的值并不是真实的值，需要将多余的字节去掉
    // 例如：0x20000001读取
    // 实际读取的是0x20000000的值为0x12345678
    // 0x20000000:0x78
    // 0x20000001:0x56
    // 0x20000002:0x34
    // 0x20000003:0x12
    // 此时右移8位，0x123456就是真实读取0x20000001的值
    uint32_t shift = (addr & 3) * 8;
    return (val_aligned >> shift) & 0xff;
}

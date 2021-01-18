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
#include <string.h>
#include "esp_partition.h"
#include "esp_log.h"
#include "esp_core_dump_priv.h"
#include "esp_flash_internal.h"
#include "esp_flash_encrypt.h"
#include "esp_rom_crc.h"

const static DRAM_ATTR char TAG[] __attribute__((unused)) = "esp_core_dump_flash";

#if CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH

typedef struct _core_dump_partition_t
{
    uint32_t start; // core dump 分区起始地址
    uint32_t size;  // core dump 分区大小
} core_dump_partition_t;

typedef struct _core_dump_flash_config_t
{
    core_dump_partition_t partition;        // core dump 的分区配置
    core_dump_crc_t partition_config_crc;   // core dump 配置的CRC
} core_dump_flash_config_t;

// core dump flash 数据
static core_dump_flash_config_t s_core_flash_config;

#ifdef CONFIG_SPI_FLASH_USE_LEGACY_IMPL
#define ESP_COREDUMP_FLASH_WRITE(_off_, _data_, _len_)           spi_flash_write(_off_, _data_, _len_)
#define ESP_COREDUMP_FLASH_WRITE_ENCRYPTED(_off_, _data_, _len_) spi_flash_write_encrypted(_off_, _data_, _len_)
#define ESP_COREDUMP_FLASH_ERASE(_off_, _len_)                   spi_flash_erase_range(_off_, _len_)
#else
#define ESP_COREDUMP_FLASH_WRITE(_off_, _data_, _len_)           esp_flash_write(esp_flash_default_chip, _data_, _off_, _len_)
#define ESP_COREDUMP_FLASH_WRITE_ENCRYPTED(_off_, _data_, _len_) esp_flash_write_encrypted(esp_flash_default_chip, _off_, _data_, _len_)
#define ESP_COREDUMP_FLASH_ERASE(_off_, _len_)                   esp_flash_erase_region(esp_flash_default_chip, _off_, _len_)
#endif

static esp_err_t esp_core_dump_flash_custom_write(uint32_t address, const void *buffer, uint32_t length)
{
    esp_err_t err = ESP_OK;

    if (esp_flash_encryption_enabled()) {
        err = ESP_COREDUMP_FLASH_WRITE_ENCRYPTED(address, buffer, length);
    } else {
        err = ESP_COREDUMP_FLASH_WRITE(address, buffer, length);
    }

    return err;
}

esp_err_t esp_core_dump_image_get(size_t* out_addr, size_t *out_size);

// 获取flash中coredump分区的CRC校验值
static inline core_dump_crc_t esp_core_dump_calc_flash_config_crc(void)
{
    return esp_rom_crc32_le(0, (uint8_t const *)&s_core_flash_config.partition, sizeof(s_core_flash_config.partition));
}

// flash 中 core dump 分区的初始化
void esp_core_dump_flash_init(void)
{
    const esp_partition_t *core_part = NULL;

    /* Look for the core dump partition on the flash. */
    ESP_COREDUMP_LOGI("Init core dump to flash");

    // 查找coredump flash 分区
    core_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL);
    if (!core_part) {
        ESP_COREDUMP_LOGE("No core dump partition found!");
        return;
    }
    ESP_COREDUMP_LOGI("Found partition '%s' @ %x %d bytes", core_part->label, core_part->address, core_part->size);
    s_core_flash_config.partition.start      = core_part->address;
    s_core_flash_config.partition.size       = core_part->size;
    s_core_flash_config.partition_config_crc = esp_core_dump_calc_flash_config_crc();
}

// coredump 写入flash
// 每次调用传参很小的话，首先放入缓冲区
// 数据较大的话就以缓冲区的倍数直接写入flash
// 剩余的数据放入缓冲区
static esp_err_t esp_core_dump_flash_write_data(void *priv, uint8_t *data, uint32_t data_size)
{
    core_dump_write_data_t *wr_data = (core_dump_write_data_t *)priv;
    esp_err_t err = ESP_OK;
    uint32_t written = 0;   // 已经写入的数据长度
    uint32_t wr_sz = 0;     // 实际要写入数据的长度

    // 确保写入的数据要比分区表的长度小
    assert((wr_data->off + data_size) < s_core_flash_config.partition.size);

    // 缓冲区中已经有数据
    if (wr_data->cached_bytes) {
        /* Some bytes are in the cache, let's continue filling the cache
         * with the data received as parameter. Let's calculate the maximum
         * amount of bytes we can still fill the cache with. */
        // 缓存中有一些字节，让我们继续将接收到的数据作为参数填充到缓存中。 
        // 让我们计算仍然可以用来填充缓存的最大字节数。

        if ((COREDUMP_CACHE_SIZE - wr_data->cached_bytes) > data_size)  // 剩余缓存足够存放即将写入的数据
            wr_sz = data_size;
        else                                                            // 剩余缓存不够存放即将写入的数据
            wr_sz = COREDUMP_CACHE_SIZE - wr_data->cached_bytes;

        // 把要写入的数据拷贝到缓冲数组中
        memcpy(&wr_data->cached_data[wr_data->cached_bytes], data, wr_sz);
        wr_data->cached_bytes += wr_sz;

        // 缓冲区满了，将缓冲区数据写入flash
        if (wr_data->cached_bytes == COREDUMP_CACHE_SIZE) {
            // 缓冲区满了，将其刷新到flash
            err = esp_core_dump_flash_custom_write(s_core_flash_config.partition.start + wr_data->off,
                                                   wr_data->cached_data,
                                                   COREDUMP_CACHE_SIZE);
            if (err != ESP_OK) {
                ESP_COREDUMP_LOGE("Failed to write cached data to flash (%d)!", err);
                return err;
            }
            /* The offset of the next data that will be written onto the flash
             * can now be increased. */
            wr_data->off += COREDUMP_CACHE_SIZE;

            // 用flash上新写入的数据更新校验和
            esp_core_dump_checksum_update(wr_data, &wr_data->cached_data, COREDUMP_CACHE_SIZE);

            // 重置缓冲区
            wr_data->cached_bytes = 0;
            memset(wr_data->cached_data, 0, COREDUMP_CACHE_SIZE);
        }

        written += wr_sz;       // 已经写入的长度
        data_size -= wr_sz;     // 剩余长度
    }

    /* 
     * 不使用缓冲区，计算直接写入flash的字节数，该长度是写入块的最小值的整数倍
     * 例如：如果COREDUMP_CACHE_SIZE等于32，值为下表
     * +---------+-----------------------+
     * |         |       data_size       |
     * +---------+---+----+----+----+----+
     * |         | 0 | 31 | 32 | 40 | 64 |
     * +---------+---+----+----+----+----+
     * | (blocks | 0 | 0  | 1  | 1  | 2) |
     * +---------+---+----+----+----+----+
     * | wr_sz   | 0 | 0  | 32 | 32 | 64 |
     * +---------+---+----+----+----+----+
     * 计算即将写入的长度换算为COREDUMP_CACHE_SIZE整数倍
     */
    wr_sz = (data_size / COREDUMP_CACHE_SIZE) * COREDUMP_CACHE_SIZE;
    if (wr_sz) {
        // 将相邻字节数的数据写入flash，不使用缓冲区
        err = esp_core_dump_flash_custom_write(s_core_flash_config.partition.start + wr_data->off, data + written, wr_sz);

        if (err != ESP_OK) {
            ESP_COREDUMP_LOGE("Failed to write data to flash (%d)!", err);
            return err;
        }

        // 用新写入的数据更新校验和
        esp_core_dump_checksum_update(wr_data, data + written, wr_sz);
        wr_data->off += wr_sz;
        written += wr_sz;
        data_size -= wr_sz;
    }

    // 写入flash后剩余的数据，将其放入缓冲区，以后写入flash
    if (data_size > 0) {
        memcpy(&wr_data->cached_data, data + written, data_size);
        wr_data->cached_bytes = data_size;
    }

    return ESP_OK;
}

// coredump 写入flsh的准备工作
static esp_err_t esp_core_dump_flash_write_prepare(void *priv, uint32_t *data_len)
{
    core_dump_write_data_t *wr_data = (core_dump_write_data_t *)priv;
    esp_err_t err = ESP_OK;
    uint32_t sec_num = 0;
    uint32_t cs_len = 0;

    // 获取最终的校验和长度
    cs_len = esp_core_dump_checksum_finish(wr_data, NULL);

    // 根据缓冲区大小，在core dump文件末尾可能需要一定的填充
    uint32_t padding = 0;                                       // 填充长度
    const uint32_t modulo = *data_len % COREDUMP_CACHE_SIZE;    // 取余
    if (modulo != 0) {
        // 数据长度不是COREDUMP_CACHE_SIZE整数倍，需要填充
        padding = COREDUMP_CACHE_SIZE - modulo;
    }

    // 检查couredump分区中是否有足够的空间
    if ((*data_len + padding + cs_len) > s_core_flash_config.partition.size) {
        ESP_COREDUMP_LOGE("Not enough space to save core dump!");
        return ESP_ERR_NO_MEM;
    }

    // coredump分区有足够的空间，加入padding和校验和长度
    *data_len += padding + cs_len;

    memset(wr_data, 0, sizeof(core_dump_write_data_t));

    // 为了擦除flash中准确数量的数据，需要计算coredump文件需要多少SPI FLASH块
    sec_num = *data_len / SPI_FLASH_SEC_SIZE;
    if (*data_len % SPI_FLASH_SEC_SIZE) {
        sec_num++;
    }

    ESP_COREDUMP_LOGI("Erase flash %d bytes @ 0x%x", sec_num * SPI_FLASH_SEC_SIZE, s_core_flash_config.partition.start + 0);
    assert(sec_num * SPI_FLASH_SEC_SIZE <= s_core_flash_config.partition.size);

    // 擦除需要的几个SPI FLASH块
    err = ESP_COREDUMP_FLASH_ERASE(s_core_flash_config.partition.start + 0, sec_num * SPI_FLASH_SEC_SIZE);
    if (err != ESP_OK) {
        ESP_COREDUMP_LOGE("Failed to erase flash (%d)!", err);
    }

    return err;
}

// coredump开始写入flash
static esp_err_t esp_core_dump_flash_write_start(void *priv)
{
    core_dump_write_data_t *wr_data = (core_dump_write_data_t *)priv;

    // 初始化校验和
    esp_core_dump_checksum_init(wr_data);
    return ESP_OK;
}

// coredump写入flash结束
static esp_err_t esp_core_dump_flash_write_end(void *priv)
{
    esp_err_t err = ESP_OK;
    void* checksum = NULL;
    uint32_t cs_len = 0;
    core_dump_write_data_t *wr_data = (core_dump_write_data_t *)priv;

    /* Get the size, in bytes of the checksum. */
    cs_len  = esp_core_dump_checksum_finish(wr_data, NULL);

    /* Flush cached bytes, including the zero padding at the end (if any). */
    if (wr_data->cached_bytes) {
        err = esp_core_dump_flash_custom_write(s_core_flash_config.partition.start + wr_data->off,
                                               wr_data->cached_data,
                                               COREDUMP_CACHE_SIZE);

        if (err != ESP_OK) {
            ESP_COREDUMP_LOGE("Failed to flush cached data to flash (%d)!", err);
            return err;
        }

        /* Update the checksum with the data written, including the padding. */
        esp_core_dump_checksum_update(wr_data, wr_data->cached_data, COREDUMP_CACHE_SIZE);
        wr_data->off += COREDUMP_CACHE_SIZE;
        wr_data->cached_bytes = 0;
    }

    /* All data have been written to the flash, the cache is now empty, we can
     * terminate the checksum calculation. */
    esp_core_dump_checksum_finish(wr_data, &checksum);

    /* Use the cache to write the checksum if its size doesn't match the requirements.
     * (e.g. its size is not a multiple of 32) */
    if (cs_len < COREDUMP_CACHE_SIZE) {
        /* Copy the checksum into the cache. */
        memcpy(wr_data->cached_data, checksum, cs_len);

        /* Fill the rest of the cache with zeros. */
        memset(wr_data->cached_data + cs_len, 0, COREDUMP_CACHE_SIZE - cs_len);

        /* Finally, write the checksum on the flash, using the cache. */
        err = esp_core_dump_flash_custom_write(s_core_flash_config.partition.start + wr_data->off,
                                               wr_data->cached_data,
                                               COREDUMP_CACHE_SIZE);
    } else {
        /* In that case, the length of the checksum must be a multiple of 16. */
        assert(cs_len % 16 == 0);
        err = esp_core_dump_flash_custom_write(s_core_flash_config.partition.start + wr_data->off, checksum, cs_len);
    }

    if (err != ESP_OK) {
        ESP_COREDUMP_LOGE("Failed to flush cached data to flash (%d)!", err);
        return err;
    }
    wr_data->off += cs_len;
    ESP_COREDUMP_LOGI("Write end offset 0x%x, check sum length %d", wr_data->off, cs_len);
    return err;
}

void esp_core_dump_to_flash(panic_info_t *info)
{
    static core_dump_write_config_t wr_cfg = { 0 };
    static core_dump_write_data_t wr_data = { 0 };

    /* Check core dump partition configuration. */
    core_dump_crc_t crc = esp_core_dump_calc_flash_config_crc();
    if (s_core_flash_config.partition_config_crc != crc) {
        ESP_COREDUMP_LOGE("Core dump flash config is corrupted! CRC=0x%x instead of 0x%x", crc, s_core_flash_config.partition_config_crc);
        return;
    }

    /* Make sure that the partition can at least data length. */
    if (s_core_flash_config.partition.start == 0 || s_core_flash_config.partition.size < sizeof(uint32_t)) {
        ESP_COREDUMP_LOGE("Invalid flash partition config!");
        return;
    }

    /* Initialize non-OS flash access critical section. */
    spi_flash_guard_set(&g_flash_guard_no_os_ops);
    esp_flash_app_disable_protect(true);

    /* Register the callbacks that will be called later by the generic part. */
    wr_cfg.prepare = esp_core_dump_flash_write_prepare;
    wr_cfg.start = esp_core_dump_flash_write_start;
    wr_cfg.end = esp_core_dump_flash_write_end;
    wr_cfg.write = (esp_core_dump_flash_write_data_t) esp_core_dump_flash_write_data;
    wr_cfg.priv = &wr_data;

    ESP_COREDUMP_LOGI("Save core dump to flash...");
    esp_core_dump_write(info, &wr_cfg);
    ESP_COREDUMP_LOGI("Core dump has been saved to flash.");
}

void esp_core_dump_init(void)
{
    size_t core_data_sz = 0;
    size_t core_data_addr = 0;
    esp_core_dump_flash_init();
    if (esp_core_dump_image_get(&core_data_addr, &core_data_sz) == ESP_OK && core_data_sz > 0) {
        ESP_COREDUMP_LOGI("Found core dump %d bytes in flash @ 0x%x", core_data_sz, core_data_addr);
    }
}
#endif

esp_err_t esp_core_dump_image_get(size_t* out_addr, size_t *out_size)
{
    spi_flash_mmap_handle_t core_data_handle = { 0 };
    esp_err_t err = ESP_OK;
    const void *core_data = NULL;

    if (out_addr == NULL || out_size == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Find the partition that could potentially contain a (previous) core dump. */
    const esp_partition_t *core_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                                ESP_PARTITION_SUBTYPE_DATA_COREDUMP,
                                                                NULL);
    if (!core_part) {
        ESP_LOGE(TAG, "No core dump partition found!");
        return ESP_ERR_NOT_FOUND;
    }
    if (core_part->size < sizeof(uint32_t)) {
        ESP_LOGE(TAG, "Too small core dump partition!");
        return ESP_ERR_INVALID_SIZE;
    }

    /* The partition has been found, map its first uint32_t value, which
     * describes the core dump file size. */
    err = esp_partition_mmap(core_part, 0,  sizeof(uint32_t),
                             SPI_FLASH_MMAP_DATA, &core_data, &core_data_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mmap core dump data (%d)!", err);
        return err;
    }

    /* Extract the size and unmap the partition. */
    uint32_t *dw = (uint32_t *)core_data;
    *out_size = *dw;
    spi_flash_munmap(core_data_handle);
    if (*out_size == 0xFFFFFFFF) {
        ESP_LOGD(TAG, "Blank core dump partition!");
        return ESP_ERR_INVALID_SIZE;
    } else if ((*out_size < sizeof(uint32_t)) || (*out_size > core_part->size)) {
        ESP_LOGE(TAG, "Incorrect size of core dump image: %d", *out_size);
        return ESP_ERR_INVALID_SIZE;
    }

    /* Remap the full core dump parition, including the final checksum. */
    err = esp_partition_mmap(core_part, 0, *out_size,
                             SPI_FLASH_MMAP_DATA, &core_data, &core_data_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mmap core dump data (%d)!", err);
        return err;
    }

    // TODO: check CRC or SHA basing on the version of core dump image stored in flash
#if CONFIG_ESP_COREDUMP_CHECKSUM_CRC32
    uint32_t *crc = (uint32_t *)(((uint8_t *)core_data) + *out_size);
    /* Decrement crc to make it point onto our CRC checksum. */
    crc--;

    /* Calculate CRC checksum again over core dump data read from the flash,
     * excluding CRC field. */
    core_dump_crc_t cur_crc = esp_rom_crc32_le(0, (uint8_t const *)core_data, *out_size - sizeof(core_dump_crc_t));
    if (*crc != cur_crc) {
        ESP_LOGD(TAG, "Core dump CRC offset 0x%x, data size: %u",
                (uint32_t)((uint32_t)crc - (uint32_t)core_data), *out_size);
        ESP_LOGE(TAG, "Core dump data CRC check failed: 0x%x -> 0x%x!", *crc, cur_crc);
        spi_flash_munmap(core_data_handle);
        return ESP_ERR_INVALID_CRC;
    }
#elif CONFIG_ESP_COREDUMP_CHECKSUM_SHA256
    /* sha256_ptr will point to our checksum. */
    uint8_t* sha256_ptr = (uint8_t*)(((uint8_t *)core_data) + *out_size);
    sha256_ptr -= COREDUMP_SHA256_LEN;
    ESP_LOGD(TAG, "Core dump data offset, size: %d, %u!",
                    (uint32_t)((uint32_t)sha256_ptr - (uint32_t)core_data), *out_size);

    /* The following array will contain the SHA256 value of the core dump data
     * read from the flash. */
    unsigned char sha_output[COREDUMP_SHA256_LEN];
    mbedtls_sha256_context ctx;
    ESP_LOGI(TAG, "Calculate SHA256 for coredump:");
    (void)esp_core_dump_sha(&ctx, core_data, *out_size - COREDUMP_SHA256_LEN, sha_output);

    /* Compare the two checksums, if they are different, the file on the flash
     * may be corrupted. */
    if (memcmp((uint8_t*)sha256_ptr, (uint8_t*)sha_output, COREDUMP_SHA256_LEN) != 0) {
        ESP_LOGE(TAG, "Core dump data SHA256 check failed:");
        esp_core_dump_print_sha256("Calculated SHA256", (uint8_t*)sha_output);
        esp_core_dump_print_sha256("Image SHA256",(uint8_t*)sha256_ptr);
        spi_flash_munmap(core_data_handle);
        return ESP_ERR_INVALID_CRC;
    } else {
        ESP_LOGI(TAG, "Core dump data SHA256 is correct");
    }
#endif
    spi_flash_munmap(core_data_handle);

    *out_addr = core_part->address;
    return ESP_OK;
}

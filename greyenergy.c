/*
YARA module developed to parse the GreyEnergy 
packer, decrypting only the first part of the 
appdata in order to confirm the detection.

After the compilation, it is possible to detect the
malicious file just using the new keyword 'is_packed'.

Rule example:
[rule]
import "pe"
import "greyenergy"

rule GreyEnergyPacker {
  condition:
    greyenergy.is_packed(pe.overlay.offset)
}
[/rule]

Tested on the following GreyEnergy samples (SHA-256):
d4e97a18be820a1a3af639c9bca21c5f85a3f49a37275b37fd012faeffcb7c4a
b60c0c04badc8c5defab653c581d57505b3455817b57ee70af74311fa0b65e22

Author   : Guglielmo Fachini
Reviewer : Alessandro Di Pinto (@adipinto)
Contact  : secresearch [ @ ] nozominetworks [ . ] com
*/

#include <yara/modules.h>

#define MODULE_NAME greyenergy

#define INITIAL_KEY_SIZE  40
#define EXTENDED_KEY_SIZE 256
#define BYTES_TO_ANALYZE  3

void swap(uint8_t* x, uint8_t* y)
{
  uint8_t tmp = *y;
  *y = *x;
  *x = tmp;
}

void derive_extended_key(const uint8_t initial_key[INITIAL_KEY_SIZE], uint8_t extended_key[EXTENDED_KEY_SIZE])
{
  for (int i = 0; i < EXTENDED_KEY_SIZE; i++)
  {
    extended_key[i] = i;
  }

  int j = 0;
  uint8_t keysum = 0;
  for (int i = 0; i < EXTENDED_KEY_SIZE; i++)
  {
    keysum = (keysum + initial_key[j] + extended_key[i]) % 256;
    swap(&extended_key[i], &extended_key[keysum]);
    j = (j + 1) % INITIAL_KEY_SIZE;
  }
}

void decrypt(uint8_t* cipher, size_t cipher_size, uint8_t extended_key[EXTENDED_KEY_SIZE])
{
  int j = 1;
  uint8_t keysum = 0;
  for (int i = 0; i < cipher_size; i++)
  {
    keysum = (keysum + extended_key[j]) % 256;
    swap(&extended_key[j], &extended_key[keysum]);
    cipher[i] ^= extended_key[(extended_key[j] + extended_key[keysum]) % 256];
    j = (j + 1) % 256;
  }
}

define_function(is_packed)
{
  int64_t overlay_offset = integer_argument(1);

  if (overlay_offset < 0)
  {
    return_integer(0);
  }

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
  YR_MEMORY_BLOCK* block;

  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = block->fetch_data(block);
    if (block_data == NULL ||
        block->size < overlay_offset + INITIAL_KEY_SIZE + BYTES_TO_ANALYZE)
    {
      continue;
    }

    uint8_t extended_key[EXTENDED_KEY_SIZE];
    derive_extended_key(block_data + overlay_offset, extended_key);

    uint8_t initial_bytes[BYTES_TO_ANALYZE] = { block_data[overlay_offset + INITIAL_KEY_SIZE],
                                                block_data[overlay_offset + INITIAL_KEY_SIZE + 1],
                                                block_data[overlay_offset + INITIAL_KEY_SIZE + 2] };
    decrypt(initial_bytes, BYTES_TO_ANALYZE, extended_key);

    return_integer(initial_bytes[0] == 'M' && initial_bytes[1] == 0x00 && initial_bytes[2] == 'Z');
  }

  return_integer(0);
}

begin_declarations;
  declare_function("is_packed", "i", "i", is_packed);
end_declarations;

int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  return ERROR_SUCCESS;
}

int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}

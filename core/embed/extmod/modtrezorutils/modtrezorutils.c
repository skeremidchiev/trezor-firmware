/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "py/runtime.h"
#include "py/objstr.h"

#include "version.h"

#if MICROPY_PY_TREZORUTILS

#include "embed/extmod/trezorobj.h"

#include <string.h>
#include "common.h"

/// def consteq(sec: bytes, pub: bytes) -> bool:
///     """
///     Compares the private information in `sec` with public, user-provided
///     information in `pub`.  Runs in constant time, corresponding to a length
///     of `pub`.  Can access memory behind valid length of `sec`, caller is
///     expected to avoid any invalid memory access.
///     """
STATIC mp_obj_t mod_trezorutils_consteq(mp_obj_t sec, mp_obj_t pub) {
  mp_buffer_info_t secbuf;
  mp_get_buffer_raise(sec, &secbuf, MP_BUFFER_READ);
  mp_buffer_info_t pubbuf;
  mp_get_buffer_raise(pub, &pubbuf, MP_BUFFER_READ);

  size_t diff = secbuf.len - pubbuf.len;
  for (size_t i = 0; i < pubbuf.len; i++) {
    const uint8_t *s = (uint8_t *)secbuf.buf;
    const uint8_t *p = (uint8_t *)pubbuf.buf;
    diff |= s[i] - p[i];
  }

  if (diff == 0) {
    return mp_const_true;
  } else {
    return mp_const_false;
  }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorutils_consteq_obj,
                                 mod_trezorutils_consteq);

#define WORDS_PER_BLOCK ((MICROPY_BYTES_PER_GC_BLOCK) / BYTES_PER_WORD)
#define BYTES_PER_BLOCK (MICROPY_BYTES_PER_GC_BLOCK)

// ATB = allocation table byte
// 0b00 = FREE -- free block
// 0b01 = HEAD -- head of a chain of blocks
// 0b10 = TAIL -- in the tail of a chain of blocks
// 0b11 = MARK -- marked head block

#define AT_FREE (0)
#define AT_HEAD (1)
#define AT_TAIL (2)
#define AT_MARK (3)

#define BLOCKS_PER_ATB (4)
#define ATB_MASK_0 (0x03)
#define ATB_MASK_1 (0x0c)
#define ATB_MASK_2 (0x30)
#define ATB_MASK_3 (0xc0)

#define ATB_0_IS_FREE(a) (((a) & ATB_MASK_0) == 0)
#define ATB_1_IS_FREE(a) (((a) & ATB_MASK_1) == 0)
#define ATB_2_IS_FREE(a) (((a) & ATB_MASK_2) == 0)
#define ATB_3_IS_FREE(a) (((a) & ATB_MASK_3) == 0)

#define BLOCK_SHIFT(block) (2 * ((block) & (BLOCKS_PER_ATB - 1)))
#define ATB_GET_KIND(block) ((MP_STATE_MEM(gc_alloc_table_start)[(block) / BLOCKS_PER_ATB] >> BLOCK_SHIFT(block)) & 3)
#define ATB_ANY_TO_FREE(block) do { MP_STATE_MEM(gc_alloc_table_start)[(block) / BLOCKS_PER_ATB] &= (~(AT_MARK << BLOCK_SHIFT(block))); } while (0)
#define ATB_FREE_TO_HEAD(block) do { MP_STATE_MEM(gc_alloc_table_start)[(block) / BLOCKS_PER_ATB] |= (AT_HEAD << BLOCK_SHIFT(block)); } while (0)
#define ATB_FREE_TO_TAIL(block) do { MP_STATE_MEM(gc_alloc_table_start)[(block) / BLOCKS_PER_ATB] |= (AT_TAIL << BLOCK_SHIFT(block)); } while (0)
#define ATB_HEAD_TO_MARK(block) do { MP_STATE_MEM(gc_alloc_table_start)[(block) / BLOCKS_PER_ATB] |= (AT_MARK << BLOCK_SHIFT(block)); } while (0)
#define ATB_MARK_TO_HEAD(block) do { MP_STATE_MEM(gc_alloc_table_start)[(block) / BLOCKS_PER_ATB] &= (~(AT_TAIL << BLOCK_SHIFT(block))); } while (0)

#define BLOCK_FROM_PTR(ptr) (((byte*)(ptr) - MP_STATE_MEM(gc_pool_start)) / BYTES_PER_BLOCK)
#define PTR_FROM_BLOCK(block) (((block) * BYTES_PER_BLOCK + (uintptr_t)MP_STATE_MEM(gc_pool_start)))
#define ATB_FROM_BLOCK(bl) ((bl) / BLOCKS_PER_ATB)

// ptr should be of type void*
#define VERIFY_PTR(ptr) ( \
        ((uintptr_t)(ptr) & (BYTES_PER_BLOCK - 1)) == 0      /* must be aligned on a block */ \
        && ptr >= (void*)MP_STATE_MEM(gc_pool_start)     /* must be above start of pool */ \
        && ptr < (void*)MP_STATE_MEM(gc_pool_end)        /* must be below end of pool */ \
    )

size_t find_allocated_size(void *ptr) {
  if (!ptr) {
    return 0;
  }

  if (!VERIFY_PTR(ptr)) {
    printf("failed to verify ptr: %p\n", ptr);
    return 0;
  }

  size_t block = BLOCK_FROM_PTR(ptr);
  if (ATB_GET_KIND(block) != AT_HEAD) {
    printf("ptr %p is not allocation head?\n", ptr);
    return 0;
  }
  size_t n = 0;
  do { ++n; } while (ATB_GET_KIND(block + n) == AT_TAIL);
  return n;
}

void dump_value(FILE* out, mp_obj_t value);

static void print_type(FILE* out, const char * typename, size_t alloc, const char * shortval, void * ptr) {
  fprintf(out, "\"type\": \"%s\", \"alloc\": %ld, \"ptr\": \"%p\"", typename, alloc, ptr);
  if (shortval) {
    fprintf(out, ", \"shortval\": \"%s\"", shortval);
  } else {
    fprintf(out, ", \"shortval\": null");
  }
}

static void print_repr(FILE* out, const char * strbuf, size_t buflen) {
  fprintf(out, "\"");
  for (size_t i = 0; i < buflen; ++i) {
    if (strbuf[i] == '\\') fprintf(out, "\\\\");
    else if (strbuf[i] == '"') fprintf(out, "\\\"");
    else if (strbuf[i] >= 0x20 && strbuf[i] <= 0x7e) fprintf(out, "%c", strbuf[i]);
    else fprintf(out, "\\\\x%02x", (unsigned char)strbuf[i]);
  }
  fprintf(out, "\"");
}

void dump_dict_inner(FILE* out, mp_obj_dict_t *dict) {
  size_t blocks = find_allocated_size(dict) + find_allocated_size(dict->map.table);
  print_type(out, "dict", blocks, NULL, dict);
  fprintf(out, ", \"children\": [");
  bool first = true;
  for (size_t i = 0; i < dict->map.alloc; ++i) {
    if (!mp_map_slot_is_filled(&dict->map, i)) continue;
    if (!first) fprintf(out, ",\n");
    first = false;
    fprintf(out, "{\"key\": ");
    dump_value(out, dict->map.table[i].key);
    fprintf(out, ",\n\"value\": ");
    dump_value(out, dict->map.table[i].value);
    fprintf(out, "}");
  }
  fprintf(out, "]");
}

void dump_value(FILE* out, mp_obj_t value) {
  char num_buf[100];
  fprintf(out, "{");
  
  if (mp_obj_is_qstr(value)) {
    mp_int_t q = MP_OBJ_QSTR_VALUE(value);
    print_type(out, "qstr", 0, qstr_str(q), NULL);
    goto end;
  }

  if (mp_obj_is_small_int(value)) {
    snprintf(num_buf, 100, "%ld", MP_OBJ_SMALL_INT_VALUE(value));
    print_type(out, "smallint", 0, num_buf, NULL);
    goto end;
  }
  
  if (!VERIFY_PTR(value)) {
    print_type(out, "romdata", 0, NULL, value);
    goto end;
  }
  
  size_t block = BLOCK_FROM_PTR(value);
  switch (ATB_GET_KIND(block)) {
    case AT_HEAD:
      // all is ok
      ATB_HEAD_TO_MARK(block);
      break;
    case AT_TAIL:
      printf("===== pointer to tail???\n");
      break;
    case AT_MARK:
      print_type(out, "already_dumped", 0, NULL, value);
      goto end;
  }

  if (mp_obj_is_str_or_bytes(value)) {
    size_t len = 0;
    const char * val = mp_obj_str_get_data(value, &len);
    print_type(out, "anystr", find_allocated_size(value), NULL, value);
    fprintf(out, ", \"val\": ");
    print_repr(out, val, len);
    goto end;
  }
  
  if (mp_obj_is_type(value, &mp_type_dict)) {
    dump_dict_inner(out, value);
    goto end;
  }
  
  if (mp_obj_is_type(value, &mp_type_module)) {
    print_type(out, "module", find_allocated_size(value), NULL, value);
    fprintf(out, ", \"globals\": {");
    dump_dict_inner(out, ((mp_obj_module_t*)value)->globals);
    fprintf(out, "}");
    goto end;
  }
  
  print_type(out, "unknown", find_allocated_size(value), NULL, value);

end:
  fprintf(out, "}\n");
}


STATIC mp_obj_t mod_trezorutils_meminfo(mp_obj_t filename) {
  size_t fn_len;
  FILE* out = fopen(mp_obj_str_get_data(filename, &fn_len), "w");
  fprintf(out, "{");
  dump_dict_inner(out, MP_STATE_THREAD(dict_locals));
  fprintf(out, "}\n");
  fclose(out);
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorutils_meminfo_obj,
                                 mod_trezorutils_meminfo);
/// def memcpy(
///     dst: bytearray, dst_ofs: int, src: bytes, src_ofs: int, n: int
/// ) -> int:
///     """
///     Copies at most `n` bytes from `src` at offset `src_ofs` to
///     `dst` at offset `dst_ofs`.  Returns the number of actually
///     copied bytes.
///     """
STATIC mp_obj_t mod_trezorutils_memcpy(size_t n_args, const mp_obj_t *args) {
  mp_arg_check_num(n_args, 0, 5, 5, false);

  mp_buffer_info_t dst;
  mp_get_buffer_raise(args[0], &dst, MP_BUFFER_WRITE);
  uint32_t dst_ofs = trezor_obj_get_uint(args[1]);

  mp_buffer_info_t src;
  mp_get_buffer_raise(args[2], &src, MP_BUFFER_READ);
  uint32_t src_ofs = trezor_obj_get_uint(args[3]);

  uint32_t n = trezor_obj_get_uint(args[4]);

  size_t dst_rem = (dst_ofs < dst.len) ? dst.len - dst_ofs : 0;
  size_t src_rem = (src_ofs < src.len) ? src.len - src_ofs : 0;
  size_t ncpy = MIN(n, MIN(src_rem, dst_rem));

  memmove(((char *)dst.buf) + dst_ofs, ((const char *)src.buf) + src_ofs, ncpy);

  return mp_obj_new_int(ncpy);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorutils_memcpy_obj, 5, 5,
                                           mod_trezorutils_memcpy);

/// def halt(msg: str = None) -> None:
///     """
///     Halts execution.
///     """
STATIC mp_obj_t mod_trezorutils_halt(size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t msg;
  if (n_args > 0 && mp_get_buffer(args[0], &msg, MP_BUFFER_READ)) {
    ensure(secfalse, msg.buf);
  } else {
    ensure(secfalse, "halt");
  }
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorutils_halt_obj, 0, 1,
                                           mod_trezorutils_halt);

#define PASTER(s) MP_QSTR_##s
#define MP_QSTR(s) PASTER(s)

/// GITREV: str
/// VERSION_MAJOR: int
/// VERSION_MINOR: int
/// VERSION_PATCH: int
/// MODEL: str
/// EMULATOR: bool
/// BITCOIN_ONLY: bool

STATIC const mp_rom_map_elem_t mp_module_trezorutils_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_trezorutils)},
    {MP_ROM_QSTR(MP_QSTR_consteq), MP_ROM_PTR(&mod_trezorutils_consteq_obj)},
    {MP_ROM_QSTR(MP_QSTR_meminfo), MP_ROM_PTR(&mod_trezorutils_meminfo_obj)},
    {MP_ROM_QSTR(MP_QSTR_memcpy), MP_ROM_PTR(&mod_trezorutils_memcpy_obj)},
    {MP_ROM_QSTR(MP_QSTR_halt), MP_ROM_PTR(&mod_trezorutils_halt_obj)},
    // various built-in constants
    {MP_ROM_QSTR(MP_QSTR_GITREV), MP_ROM_QSTR(MP_QSTR(GITREV))},
    {MP_ROM_QSTR(MP_QSTR_VERSION_MAJOR), MP_ROM_INT(VERSION_MAJOR)},
    {MP_ROM_QSTR(MP_QSTR_VERSION_MINOR), MP_ROM_INT(VERSION_MINOR)},
    {MP_ROM_QSTR(MP_QSTR_VERSION_PATCH), MP_ROM_INT(VERSION_PATCH)},
    {MP_ROM_QSTR(MP_QSTR_MODEL), MP_ROM_QSTR(MP_QSTR(TREZOR_MODEL))},
#ifdef TREZOR_EMULATOR
    {MP_ROM_QSTR(MP_QSTR_EMULATOR), mp_const_true},
#else
    {MP_ROM_QSTR(MP_QSTR_EMULATOR), mp_const_false},
#endif
#if BITCOIN_ONLY
    {MP_ROM_QSTR(MP_QSTR_BITCOIN_ONLY), mp_const_true},
#else
    {MP_ROM_QSTR(MP_QSTR_BITCOIN_ONLY), mp_const_false},
#endif
};

STATIC MP_DEFINE_CONST_DICT(mp_module_trezorutils_globals,
                            mp_module_trezorutils_globals_table);

const mp_obj_module_t mp_module_trezorutils = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_trezorutils_globals,
};

MP_REGISTER_MODULE(MP_QSTR_trezorutils, mp_module_trezorutils,
                   MICROPY_PY_TREZORUTILS);

#endif  // MICROPY_PY_TREZORUTILS

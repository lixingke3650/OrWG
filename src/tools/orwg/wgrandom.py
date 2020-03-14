#! python3

import random

SBOX_SIZE = 1024
NEWLINE = '\n'
TAB = '	'
FILENAME_ORWG_H = 'orwg.h'
FILENAME_ORWG_C = 'orwg.c'

def output_orwg_h():
	content  = ''
	content += '/* '												+ NEWLINE
	content += ' * lixingke3650@gmail.com'							+ NEWLINE
	content += ' */'												+ NEWLINE
	content += ''													+ NEWLINE
	content += '#ifndef _WG_ORWG_H'									+ NEWLINE
	content += '#define _WG_ORWG_H'									+ NEWLINE
	content += ''													+ NEWLINE
	content += '#define WG_DEVICE_SBOX_SIZE ' + str(SBOX_SIZE)		+ NEWLINE
	content += ''													+ NEWLINE
	content += 'extern u16 SBox_Counter;'							+ NEWLINE
	content += 'extern __le32 SBox[];'								+ NEWLINE
	content += ''													+ NEWLINE
	content += 'static inline __le32 wg_device_get_random(void)'	+ NEWLINE
	content += '{'													+ NEWLINE
	content += '	if (SBox_Counter >= WG_DEVICE_SBOX_SIZE) {'		+ NEWLINE
	content += '		SBox_Counter = 0;'							+ NEWLINE
	content += '	}'												+ NEWLINE
	content += '	return SBox[SBox_Counter++];'					+ NEWLINE
	content += '}'													+ NEWLINE
	content += ''													+ NEWLINE
	content += '#endif /* _WG_ORWG_H */'							+ NEWLINE

	fd = open(FILENAME_ORWG_H, 'w')
	fd.write(content)
	fd.close()

def output_orwg_c():
	content  = ''
	content += '/* '                       + NEWLINE
	content += ' * lixingke3650@gmail.com' + NEWLINE
	content += ' */'                       + NEWLINE
	content += ''                          + NEWLINE
	content += '#include "orwg.h"'         + NEWLINE
	content += ''                          + NEWLINE
	content += 'u16 SBox_Counter = 0;'     + NEWLINE
	content += ''                          + NEWLINE
	content += generate_sbox()             + NEWLINE

	fd = open(FILENAME_ORWG_C, 'w')
	fd.write(content)
	fd.close()

def generate_sbox():
	ELE_NUMBERS_INLINE = 8
	Pool = ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F']

	Sbox = ''
	Sbox += '__le32 SBox[WG_DEVICE_SBOX_SIZE] = {' + NEWLINE
	for _ in range(int(SBOX_SIZE/ELE_NUMBERS_INLINE)):
		Sbox += TAB
		for _ in range(ELE_NUMBERS_INLINE):
			temp = random.choice(Pool) + random.choice(Pool) + random.choice(Pool) + random.choice(Pool)
			Sbox += '0x' + temp + ', '
		Sbox += NEWLINE
	Sbox += '};' + NEWLINE
	return (Sbox)

if __name__ == '__main__':
	output_orwg_h()
	output_orwg_c()
/* 
 * lixingke3650@gmail.com
 */

#ifndef _WG_ORWG_H
#define _WG_ORWG_H

#define WG_DEVICE_SBOX_SIZE 1024

extern u16 SBox_Counter;
extern __le32 SBox[];

static inline __le32 wg_device_get_random(void)
{
	if (SBox_Counter >= WG_DEVICE_SBOX_SIZE) {
		SBox_Counter = 0;
	}
	return SBox[SBox_Counter++];
}

#endif /* _WG_ORWG_H */

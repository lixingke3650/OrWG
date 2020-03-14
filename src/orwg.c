/* 
 * lixingke3650@gmail.com
 */

#include "orwg.h"

u16 SBox_Counter = 0;

__le32 SBox[WG_DEVICE_SBOX_SIZE] = {
	0x829C, 0xA812, 0xD290, 0xC8E8, 0x77CF, 0xB6E7, 0x792E, 0xCBD4, 
	0xD350, 0x56D5, 0x5599, 0xB0AA, 0xA694, 0x4059, 0x398C, 0xAD3A, 
	0xF6B3, 0xFB65, 0xFE11, 0x80FD, 0x73A1, 0x9F37, 0x19E5, 0xB112, 
	0x9B6B, 0xDF19, 0x18EE, 0xF686, 0x2F52, 0x211E, 0x29CE, 0xEF3F, 
	0xAADF, 0x3D18, 0x2F04, 0xE7D0, 0x1685, 0xA906, 0x5A63, 0x60F7, 
	0x4761, 0x2402, 0x3166, 0xC434, 0xDBCE, 0xF871, 0x17AB, 0x2174, 
	0xFF8E, 0x95E7, 0x7466, 0xFDA2, 0x8EFC, 0xD270, 0xC765, 0x8158, 
	0xA95D, 0xFA86, 0x9AC5, 0x5CA4, 0xAAC5, 0x9E70, 0x89A7, 0x0158, 
	0xED19, 0x40E1, 0xBB03, 0x5740, 0xF246, 0x1DA1, 0x3607, 0xEE95, 
	0x3296, 0x5351, 0xC073, 0x6302, 0xF97B, 0x6379, 0xE19B, 0x0C8A, 
	0x643E, 0x5A05, 0x37E5, 0xACFF, 0xE976, 0xCA58, 0x6E2A, 0x91F6, 
	0x9BF1, 0x9AEE, 0xE586, 0x9DF4, 0x4C8E, 0x9A42, 0x85D9, 0xC3D3, 
	0x61DA, 0xF50B, 0x4819, 0x1B03, 0xF076, 0xF85B, 0x38DC, 0x3D77, 
	0x38E9, 0x4D30, 0xF460, 0x3E9A, 0x7DC3, 0xF494, 0xB755, 0x548A, 
	0xDDF6, 0xD6C2, 0x28CB, 0x6D64, 0x747E, 0xB9C9, 0x91DD, 0x778A, 
	0xF6F1, 0x5A41, 0x690F, 0x8987, 0x9765, 0x82F3, 0x0810, 0x6DC6, 
	0x4E8C, 0x3AD7, 0x296A, 0x9766, 0xDAD2, 0x0C0E, 0x649E, 0xED43, 
	0xEB52, 0xFFEA, 0x14BC, 0x3509, 0x2B31, 0x9F27, 0x2EEE, 0x5A60, 
	0x1679, 0xF7FF, 0xC450, 0xD40F, 0x3AEA, 0x9DCF, 0x0BFC, 0x2DB9, 
	0x3D3F, 0xB011, 0x1DDC, 0x191D, 0xDFCA, 0x4BEF, 0x7F0A, 0x888B, 
	0x30C4, 0x5DD9, 0x3B94, 0x6738, 0x72F6, 0xE31F, 0x0951, 0xDE59, 
	0xBE21, 0x3BEC, 0xCA61, 0xEF39, 0x450C, 0x50CD, 0x844E, 0xE77E, 
	0x084E, 0x4A83, 0xC5BF, 0x3411, 0xA02F, 0x5499, 0xA33B, 0x14DF, 
	0xE1B7, 0xFA09, 0x5B20, 0xBD36, 0xAECB, 0x61CB, 0x2AE3, 0x263B, 
	0xAE0C, 0xE421, 0x2B37, 0x6731, 0x3E83, 0xD1B0, 0x9676, 0x959F, 
	0x3741, 0x7E04, 0x0AC7, 0xD3A7, 0x3327, 0x1F0A, 0x0A39, 0x4781, 
	0x67A2, 0x483F, 0xCAAE, 0x4A6A, 0x51DA, 0x405F, 0x46E8, 0x8F1B, 
	0x2E42, 0xAC8C, 0x7ADD, 0xF334, 0x6715, 0xA9C0, 0x9075, 0x49C2, 
	0xA2B7, 0x397C, 0x4746, 0xA61B, 0x1253, 0x7907, 0x95F9, 0x245A, 
	0xD4DC, 0x7F04, 0x59FC, 0xC022, 0xDFA7, 0x67F1, 0x55F2, 0xD5BD, 
	0x7A89, 0x0262, 0x9626, 0x9FD8, 0xBC59, 0x0755, 0xC8F7, 0x9157, 
	0xBF14, 0x8B77, 0xBFAC, 0x8A35, 0xC46E, 0xDE86, 0xBCCB, 0x7F9D, 
	0x80B3, 0x5414, 0x79ED, 0xCAA5, 0xB89D, 0x249C, 0x583B, 0x7EAC, 
	0x698B, 0xD855, 0x247F, 0x7331, 0x0335, 0x9362, 0xC6EF, 0x4136, 
	0x2AD2, 0x27DD, 0x4AF9, 0x7D53, 0x12AF, 0xA22F, 0x84F8, 0x8E13, 
	0xDABC, 0x46AC, 0xDB0B, 0x8D5A, 0x7F85, 0x655F, 0x2235, 0xBCE7, 
	0x7757, 0x1346, 0x32F5, 0x5CC8, 0x3BBA, 0x08AB, 0x8443, 0x0B1C, 
	0x3D06, 0x0F54, 0x67D6, 0x2A51, 0xC2A3, 0xCBA6, 0x2A9E, 0xF10C, 
	0xD124, 0xD675, 0x1038, 0xF0B8, 0x8EEB, 0x36D9, 0x05DF, 0x8513, 
	0xB666, 0x4C36, 0x380F, 0xDF19, 0x119D, 0x3306, 0x1226, 0x436D, 
	0x494C, 0x25CF, 0x72AF, 0x28A5, 0xCF15, 0x3A67, 0x13F4, 0xC733, 
	0x2CF9, 0x86CF, 0x5145, 0xA229, 0x5758, 0xFFD4, 0xBAF9, 0x65B1, 
	0xF270, 0xF9D0, 0xBD67, 0xE45A, 0x1FC7, 0x9725, 0x5F37, 0xE78C, 
	0x7173, 0x3025, 0x62F6, 0x0C88, 0xC0A4, 0xAFE3, 0x99EE, 0x0698, 
	0x4103, 0x3868, 0xEE56, 0xAD92, 0x973A, 0xED00, 0x14D5, 0x2341, 
	0x190A, 0x8F0B, 0x7BA1, 0x3C50, 0xED80, 0x1557, 0xF926, 0xEBF4, 
	0x0127, 0x0793, 0x6E77, 0x4B77, 0x33AC, 0x03A2, 0x996B, 0x9F7C, 
	0xEF14, 0xE80D, 0x328B, 0x6AC0, 0x55E7, 0x68FE, 0x9BB6, 0x7D21, 
	0x4A44, 0x293C, 0xBAA3, 0xE863, 0xC92E, 0x9953, 0xE103, 0xD3F9, 
	0x4A6A, 0xB668, 0xA14A, 0x9043, 0xA7C6, 0x6B1A, 0xBC21, 0x2710, 
	0x46F9, 0x35EA, 0xB8D4, 0x70FE, 0xB9B5, 0xA65C, 0x18E6, 0x34C8, 
	0xB872, 0x3778, 0xCEC6, 0x08C5, 0xFFB1, 0x6364, 0x5931, 0xEE09, 
	0x999B, 0xAE20, 0x8418, 0xB554, 0x78E8, 0xD7C8, 0xB998, 0x96F9, 
	0x3417, 0x5A9C, 0x5720, 0x3186, 0x7143, 0xA9EA, 0x5919, 0xCCD3, 
	0xE103, 0x8D46, 0x1586, 0x0502, 0xE2D7, 0x976C, 0xC5D4, 0xD84A, 
	0x6825, 0x8A46, 0xC719, 0x2304, 0xF7B8, 0x3F13, 0x5489, 0xAE26, 
	0x17A8, 0x41C3, 0xBA2A, 0xE911, 0xB771, 0xCBA6, 0xD1CD, 0x77C7, 
	0xD22C, 0xFEC4, 0x1EDE, 0xC293, 0xC531, 0xF66F, 0x0DD2, 0xB971, 
	0xD606, 0xC2FB, 0xD243, 0xDE1D, 0x45AF, 0xB42C, 0xD6DA, 0xEF02, 
	0xF679, 0xDDE4, 0xE8ED, 0x2E18, 0xCC6C, 0x4ADB, 0xE874, 0xF5E7, 
	0x0B8D, 0x245E, 0xA80E, 0x492B, 0x37E9, 0x32A2, 0x6130, 0x0720, 
	0x2527, 0xA080, 0x0AB5, 0x30ED, 0x1D28, 0xFEA1, 0xF855, 0xDB7B, 
	0xB5DF, 0x0B86, 0x7329, 0x645E, 0xB92C, 0xF9FC, 0x85F6, 0xD9D8, 
	0xC000, 0xBC6B, 0x83CB, 0xCF35, 0x501E, 0x2F8B, 0x482D, 0x44F1, 
	0xB35E, 0x4F73, 0xB2F2, 0x2DA9, 0xAACE, 0x2CD4, 0x05F1, 0xD527, 
	0x99AE, 0xFE23, 0xD4ED, 0x2ED1, 0x98C2, 0x7568, 0x8725, 0x3307, 
	0x663E, 0xC014, 0x52E7, 0xCCFD, 0x6829, 0x5C23, 0x614A, 0xC4A2, 
	0x8BBD, 0xF474, 0x2400, 0x93A5, 0xF56A, 0x139D, 0x86D6, 0xB073, 
	0x4EAA, 0x4340, 0xA431, 0xA3E7, 0xA198, 0x3F0D, 0x61A9, 0xC8AB, 
	0xDA21, 0x0FD1, 0x833A, 0x97AE, 0x25C2, 0x61BD, 0x0179, 0x9F25, 
	0xB40E, 0x7456, 0x3660, 0x62DC, 0xFAE0, 0xA413, 0x0076, 0x3E64, 
	0x170A, 0x144E, 0x1190, 0x4CEB, 0x5D25, 0x6510, 0x37DE, 0x89E4, 
	0x0890, 0x81A1, 0x6FEB, 0x318A, 0xD388, 0x76FC, 0x1918, 0x010D, 
	0xB527, 0xE18C, 0xED4A, 0xF69F, 0x9DEA, 0x924C, 0x9EB1, 0x2FE1, 
	0xF517, 0x2FF0, 0x0D23, 0x75F4, 0xF71C, 0x9C7B, 0x52A9, 0x1C46, 
	0xCDDA, 0x3B63, 0xDD64, 0x843B, 0x1D57, 0xFEC6, 0xBDA5, 0x3D54, 
	0xC498, 0x47C0, 0x125D, 0x22A9, 0xAA9E, 0xC5FE, 0x7013, 0x63FF, 
	0xE7F4, 0x06A8, 0xADCD, 0x99C3, 0xF083, 0xFB09, 0x2B94, 0x7447, 
	0x404F, 0xD0E8, 0x3E93, 0xDB0D, 0x6034, 0x3D02, 0x2166, 0x7E9C, 
	0xDF10, 0xAA84, 0x85A8, 0xF941, 0xEC34, 0xB93F, 0x004F, 0xE843, 
	0x86C2, 0x4FBD, 0x36B4, 0x4C98, 0x8DF7, 0xD382, 0xB331, 0xB3A3, 
	0xF493, 0xEB3A, 0x6048, 0x46C8, 0x26E6, 0x2BA2, 0x8DE5, 0x182C, 
	0x26EA, 0xEE64, 0x40B7, 0x2386, 0x01B7, 0x0D41, 0x8C0E, 0xF000, 
	0xC47E, 0x5C62, 0x3F4B, 0x0799, 0xC4CD, 0x6806, 0xD426, 0x1E86, 
	0x982D, 0x86A6, 0xADDE, 0xE5B6, 0x700A, 0x8539, 0x0F09, 0x0D4A, 
	0xD747, 0x58DC, 0xBB16, 0xD25C, 0x0CBA, 0x4D07, 0xA223, 0xFAB4, 
	0xA06C, 0x6829, 0x4815, 0xD03A, 0x9F2C, 0x61AB, 0xA770, 0xE7A9, 
	0xDFA9, 0x1F57, 0x0F68, 0xA1F7, 0x8836, 0x74DE, 0x8BB6, 0x01E1, 
	0xA134, 0x8C97, 0xA31E, 0xA1E0, 0x1E84, 0x32B2, 0x32B3, 0x790B, 
	0x368E, 0xB857, 0xA8DA, 0xCC05, 0xB70A, 0xC9DC, 0xDBFA, 0xF144, 
	0x6C8B, 0x1B03, 0xC161, 0x8A93, 0x3022, 0xFE99, 0x5A2B, 0x2DC0, 
	0xE260, 0x4CCD, 0xBFD0, 0x4101, 0xF4EA, 0x0C3E, 0x0853, 0x0A80, 
	0xC993, 0x23CA, 0x6E49, 0xBCB1, 0x2E49, 0xB6D6, 0xE4FB, 0xE17C, 
	0xFCAB, 0x0537, 0xADCC, 0x3300, 0xF27E, 0xD184, 0x3261, 0xBC50, 
	0x787A, 0xB853, 0x2AEB, 0x9249, 0x58F3, 0x9E00, 0x054B, 0xE282, 
	0xC7E5, 0x70CC, 0xC854, 0xC2E8, 0x753A, 0xB048, 0xE9DB, 0xF606, 
	0xF89B, 0xA636, 0x8FE4, 0x1361, 0x7FB0, 0x7A8A, 0x8093, 0xB106, 
	0x98A7, 0xF5AE, 0x7F8C, 0x710D, 0xC62B, 0x0409, 0xAC29, 0xC09E, 
	0x64CE, 0xBAEC, 0x0A6E, 0x1B28, 0x91DF, 0x58F8, 0x0690, 0x7AC9, 
	0xD8D9, 0x0088, 0x8774, 0xA5D6, 0x219C, 0x8E77, 0x4F9A, 0xED5A, 
	0x0609, 0xDA3E, 0x3D8D, 0xAC86, 0x9511, 0xA87E, 0x3A2B, 0x9AC8, 
	0x88AC, 0x49B8, 0xFB28, 0x058A, 0xC284, 0xE715, 0x45F2, 0x347B, 
	0x30CF, 0xD84E, 0x2395, 0xC208, 0x996F, 0x18FE, 0xDC29, 0x1534, 
	0xCE75, 0xF54A, 0x7AE7, 0x39B7, 0x4BAD, 0x4D44, 0x1BFF, 0x7B7D, 
	0x21B1, 0x8C08, 0x4A00, 0x40A2, 0x70A2, 0xEDA5, 0x67B2, 0x2A94, 
	0xF589, 0x925F, 0x671C, 0x1122, 0x2FEA, 0x1058, 0x998B, 0xD6C0, 
	0x5E05, 0xAB3D, 0xE6D6, 0x9625, 0xDF69, 0x0B95, 0xDD4E, 0x84A7, 
	0xE1E9, 0x882D, 0x73E8, 0x0F83, 0x357A, 0x38C4, 0x771B, 0x621A, 
	0x9315, 0x46F1, 0x2CC3, 0x4E28, 0x7400, 0x8CD7, 0x49E0, 0x02BA, 
	0x53D6, 0xA667, 0x7881, 0xEC84, 0xB6DF, 0x487B, 0x3B65, 0x9AD1, 
	0x9E0D, 0x7721, 0x54B8, 0x1369, 0x2841, 0x7AEA, 0x7820, 0x68E8, 
	0x1661, 0xFE3C, 0x516F, 0x2E80, 0x460F, 0xFFD3, 0xDA30, 0xA24D, 
	0xBA2A, 0x95F0, 0x7CB1, 0x290B, 0xEB89, 0xE123, 0xF231, 0x9548, 
	0xE0F2, 0x6FEE, 0x5801, 0x0328, 0x295A, 0x77B1, 0x7D1D, 0xEAB3, 
	0xF0B4, 0xC885, 0x7B31, 0x186F, 0xBA0D, 0x1C2C, 0xB0F5, 0xCD04, 
	0x64B9, 0x0377, 0x40AE, 0x3748, 0xD459, 0xC3EF, 0x9F96, 0xECF7, 
	0x4E52, 0x6A3E, 0x8C0B, 0x5B9A, 0x0121, 0x9347, 0x9A70, 0x5A50, 
	0x792C, 0xA215, 0xCFE1, 0xB1D5, 0x7382, 0x1E36, 0x2676, 0xB027, 
	0xDD10, 0x923B, 0x64FA, 0xA340, 0x0F80, 0xC384, 0x3185, 0xD3F6, 
	0x124D, 0xCFF8, 0xEF23, 0x9F77, 0x3FD0, 0xC420, 0xEB3B, 0xBD2C, 
	0xBAC8, 0xBE40, 0x5554, 0xDECA, 0x765F, 0xC1C5, 0x2800, 0x53A5, 
	0x996C, 0x1DC7, 0x7B93, 0x0510, 0x70CA, 0xCFCD, 0x05DF, 0x4143, 
	0xDCCF, 0xC39B, 0x9512, 0x9075, 0x6808, 0xCE76, 0xDC48, 0x6867, 
	0x66C8, 0xCE3C, 0xCD0D, 0x964D, 0x49F3, 0xC2F3, 0x9F74, 0xB7DD, 
	0x8C11, 0xA1D2, 0xE80B, 0x4D4C, 0xE6B4, 0xE153, 0x95C4, 0x3D06, 
	0x5543, 0xC038, 0xBD57, 0x86A8, 0x8CAA, 0x1833, 0xC7F3, 0xA238, 
	0x0CE0, 0x13B2, 0x63BD, 0x920E, 0x7C3C, 0x8187, 0x2111, 0xA377, 
	0x53BD, 0xACED, 0x9859, 0x44BA, 0xDC58, 0x83C9, 0xA51E, 0x49F8, 
};

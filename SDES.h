#ifndef _SDES_H
#define _SDES_H

void encrypt(bool data[8], bool key[10]);
void decrypt(bool data[8], bool key[10]);
void asciiToBinary(char letter, bool binaryArray[8]);
char binaryToAscii(bool binary[8]);
void exclusiveOr(bool* outArray, bool* xorArray, int arraySize);

#endif
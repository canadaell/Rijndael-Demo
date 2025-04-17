#include <stdio.h>
#include <stdlib.h>

#include "rijndael.h"

void print_128bit_block(unsigned char *block) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      unsigned char value = BLOCK_ACCESS(block, i, j);

      // Print spaces before small numbers to ensure that everything is aligned
      // and looks nice
      if (value < 10) printf(" ");

      if (value < 100) printf(" ");

      printf("%d", value);
    }
    printf("\n");
  }
}

int main() {
  unsigned char plaintext[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                 9, 10, 11, 12, 13, 14, 15, 16};
  unsigned char key[16] = {50, 20, 46, 86, 67, 9, 70, 27,
                           75, 17, 51, 17, 4,  8, 6,  99};

  unsigned char *ciphertext = aes_encrypt_block(plaintext, key);
  unsigned char *recovered_plaintext = aes_decrypt_block(ciphertext, key);

  printf("############ ORIGINAL PLAINTEXT ###########\n");
  print_128bit_block(plaintext);

  printf("\n\n################ CIPHERTEXT ###############\n");
  print_128bit_block(ciphertext);

  printf("\n\n########### RECOVERED PLAINTEXT ###########\n");
  print_128bit_block(recovered_plaintext);

  free(ciphertext);
  free(recovered_plaintext);

  return 0;
}
// AES密钥扩展测试代码
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void test_key_expansion() {
    unsigned char key[16];
    unsigned char *expanded;
    
    srand(time(NULL));
    
    // 生成并测试3组随机密钥
    for(int t=0; t<3; t++) {
        // 生成随机密钥
        for(int i=0; i<16; i++) {
            key[i] = rand() % 256;
        }
        
        // 执行密钥扩展
        expanded = expand_key(key);
        
        // 打印结果
        printf("\nTest Case %d:\nKey:       ", t+1);
        for(int i=0; i<16; i++) printf("%02x", key[i]);
        
        printf("\nExpanded: ");
        for(int i=0; i<176; i++) printf("%02x", expanded[i]);
        printf("\n");
        
        free(expanded);
    }
}

int main() {
    test_key_expansion();
    return 0;
}

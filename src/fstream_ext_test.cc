#include "gtest/gtest.h"
#include <fstream>
#include "fstream_ext.h"
#include "cryptopp/osrng.h"
#include "cryptopp/aes.h"

namespace fstream_ext {

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AES;
using CryptoPP::byte;

TEST(test_fstream_ext, normal) {
    const char* input = "hello world";
    const char* filename = "/tmp/test.txt";
    const char* filename1 = "/tmp/test1.txt";
    size_t size = strlen(input) + 1;
    std::ofstream fout_normal(filename1, std::ios_base::binary);
    fout_normal.write(input, size);

    ofstream_ext fout(filename, std::ios_base::binary);
    fout.write(input, size);

    fout_normal.close();
    fout.close();

    std::ifstream fin_normal(filename1, std::ios_base::binary);

    char* output = new char[size];
    fin_normal.read(output, size);;

    fin_normal.close();

    ifstream_ext fin(filename, std::ios_base::binary);
    char* output1 = new char[size];
    fin.read(output1, size);
 
    fin.close();

    //std::cout << "out: "<<output<<"\n";
    //std::cout << "out1: "<<output1<<"\n";
  
    EXPECT_EQ(strncmp(output1, output, size), 0);

    EXPECT_STREQ(output, output1);

}


TEST(test_fstream_ext, security) {

    std::string input("hello world");
    const char* filename = "/tmp/test.txt";
    const char* filename1 = "/tmp/test1.txt";

    AutoSeededRandomPool prng;
    const int TAG_SIZE = 12;
    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));
    size_t size = input.size() + 1;
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    std::ofstream fout_normal(filename1, std::ios_base::binary);
    fout_normal.write(input.c_str(), size);
    fout_normal.close();

    ofstream_ext fout(filename, std::ios_base::binary,
                      true, key, sizeof(key), iv, sizeof(iv), TAG_SIZE);
    fout.write(input.c_str(), size);
    fout.close();

    std::ifstream fin_normal(filename1, std::ios_base::binary);

    char* output = new char[size];
    fin_normal.read(output, size);
    fin_normal.peek();
    EXPECT_TRUE(fin_normal.eof());
    fin_normal.close();
    
    ifstream_ext fin(filename, std::ios_base::binary,
                      true, key, sizeof(key), iv, sizeof(iv), TAG_SIZE);
    char* output1 = new char[size];
    
    fin.read(output1, size);
    //fin.seekg(TAG_SIZE, std::ios::cur);
    fin.peek();
    EXPECT_TRUE(fin.eof());
    fin.close();

    EXPECT_EQ(strncmp(output1, output, size), 0);

    EXPECT_STREQ(output, output1);
}

TEST(test_fstream_ext, security1) {

    std::vector<double> input = {1, 2, 3, 4};
    const char* filename = "/tmp/test.txt";
    const char* filename1 = "/tmp/test1.txt";

    AutoSeededRandomPool prng;
    const int TAG_SIZE = 12;
    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    std::ofstream fout_normal(filename1, std::ios_base::binary);
    ofstream_ext fout(filename, std::ios_base::binary,
                      true, key, sizeof(key), iv, sizeof(iv), TAG_SIZE);
    for (auto& i : input) {
        fout_normal.write(reinterpret_cast<char*>(&i), sizeof(i));
        fout.write(reinterpret_cast<char*>(&i), sizeof(i));
    }

    fout_normal.close();
    fout.close();

    std::ifstream fin_normal(filename1, std::ios_base::binary);
    ifstream_ext fin(filename, std::ios_base::binary,
                      true, key, sizeof(key), iv, sizeof(iv), TAG_SIZE);

    std::vector<double> output;
    std::vector<double> output1;
    for (int i = 0; i < input.size(); i++) {
        double r, r1;

        fin_normal.read(reinterpret_cast<char*>(&r), sizeof(r));
  
        output.emplace_back(r);

        fin.read(reinterpret_cast<char*>(&r1), sizeof(r1));
        output1.emplace_back(r1);
    }

    fin_normal.close();

    fin.close();
    for (int i = 0; i < input.size(); i++) {
        EXPECT_EQ(input[i], output[i]);
        EXPECT_EQ(input[i], output1[i]);
    }
    
}

} //namespace fstream_ext

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
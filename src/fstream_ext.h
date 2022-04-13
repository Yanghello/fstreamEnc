#pragma once

#include <fstream>
#include <streambuf>
#include "cryptopp/gcm.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/secblock.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"

namespace fstream_ext {

using CryptoPP::GCM;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AES;
using CryptoPP::SecByteBlock;
using CryptoPP::byte;
using CryptoPP::Exception;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::FileSink;

class filebuf_ext : public std::filebuf {
public:
    explicit filebuf_ext() : std::filebuf(),
                    _is_end(false), _fs(nullptr), _ef(nullptr), _df{nullptr} {}

    explicit filebuf_ext(AuthenticatedEncryptionFilter* ef) :
                                        std::filebuf(),
                                        _df(nullptr), _is_end(false),
                                        _ef(ef) {}

    // err: can't overloaded if remove 'bool decrypt'
    explicit filebuf_ext(AuthenticatedDecryptionFilter* df,
                         bool decrypt) : std::filebuf(),
                         _df(df), _is_end(false), _ef(nullptr) {}

    ~filebuf_ext() {
        this->close();
    }

protected:
    std::streamsize xsgetn(char_type* s, std::streamsize n) override {

        if (!(_ef || _df)) {
            // not a secure buf
            return std::filebuf::xsgetn(s, n);
        } else {
            // dec buf
            std::streamsize size;
            std::string plain;
            char s1[n];

            //string mac = cipher.substr(2 * n);
            try {

                size = std::filebuf::xsgetn(s1, n);
                std::string cipher(s1, s1 + n);

                _df->ChannelPut(DEFAULT_CHANNEL, (const byte*) cipher.data(), n);
                
                _df->SetRetrievalChannel(DEFAULT_CHANNEL);
                plain.resize(n);
                _df->Get((byte*) plain.data(), n);

                // is last read?
                auto cur_pos = this->pubseekoff(0, std::ios::cur, std::ios::in);
                this->pubseekoff(12, std::ios::cur, std::ios::in);
                if (traits_type::eq_int_type(sgetc(), traits_type::eof())) {
                    _is_end = true;
                } else {
                    this->pubseekpos(cur_pos, std::ios::in);
                }
                traits_type::copy(s, plain.c_str(), n);
                //return n;
                if (_is_end) {
                    _df->ChannelMessageEnd(DEFAULT_CHANNEL);
                    bool b = _df->GetLastResult();
                    if (!b) {
                        throw std::runtime_error("integrity check failed!");
                    }
                    return n;
                }
                return n;

            } catch( CryptoPP::InvalidArgument& e ) {
                std::cerr << "Caught InvalidArgument..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            } catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e ) {
                // Pushing PDATA before ADATA results in:
                //  "GMC/AES: Update was called before State_IVSet"
                std::cerr << "Caught BadState..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            } catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e ) {
                std::cerr << "Caught HashVerificationFailed..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            }

            traits_type::copy(s, plain.c_str(), n);
            return n;
        }
    }
    std::streamsize xsputn(const char_type* s, std::streamsize n) override {

        if (!(_ef || _df)) {
            // not a secure buf
            return std::filebuf::xsputn(s, n);
        } else {
            // enc buf
            std::string cipher, cipher0, cipher1;
            try {
                if (_is_end) {
                    _ef->ChannelMessageEnd(DEFAULT_CHANNEL);
                } else {
                    std::string plain(s, s + n);
                    _ef->ChannelPut(DEFAULT_CHANNEL, (const byte* ) plain.data(), n);
                }
            } catch( CryptoPP::BufferedTransformation::NoChannelSupport& e) {
                // The tag must go in to the default channel:
                //  "unknown: this object doesn't support multiple channels"
                std::cerr << "Caught NoChannelSupport..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            } catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e) {
                // Pushing PDATA before ADATA results in:
                //  "GMC/AES: Update was called before State_IVSet"
                std::cerr << "Caught BadState..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            } catch( CryptoPP::InvalidArgument& e ) {
                std::cerr << "Caught InvalidArgument..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            }
            return n;
        }
    }
    int_type sync() override {
        return std::filebuf::sync();
    }
    int_type overflow(int_type c = traits_type::eof()) {
        return std::filebuf::overflow(c);
    }
public:
    void post_process() {
        if (_ef) {
            _is_end = true;
            xsputn("", 0);
        }
        if (_df) {
            //_is_end = true;
            //char s[1];
            //xsgetn(s, 1);
        }
    }

private:
    bool _is_end;
    FileSink* _fs;
    AuthenticatedEncryptionFilter* _ef;
    AuthenticatedDecryptionFilter* _df;
};

class ofstream_ext : public std::ostream {
public:
    ofstream_ext() : std::ostream(), _e(nullptr),
                     _fs(nullptr), _ef(nullptr) {
        _fbuf = new filebuf_ext();
        this->init(_fbuf);
    }

    explicit ofstream_ext(const char* s,
                std::ios_base::openmode mode = std::ios_base::out) :
                std::ostream(), _e(nullptr), _fs(nullptr), _ef(nullptr) {
        _fbuf = new filebuf_ext();
        this->init(_fbuf);
        this->open(s, mode);
    }

    explicit ofstream_ext(const char* s,
                std::ios_base::openmode mode,
                bool sec_enhanced,
                unsigned char* key_str,
                size_t key_len,
                unsigned char* iv_str,
                size_t iv_len,
                const int TAG_SIZE) :
                std::ostream() {
        if (sec_enhanced) {
            SecByteBlock key(key_str, key_len);
            byte iv[iv_len];
            memcpy(iv, iv_str, iv_len);
            std::ofstream* fout_iv = new std::ofstream(s, mode);
            fout_iv->write((char*) iv, iv_len);
            //fout_iv.flush();
            _e = new GCM<AES>::Encryption();
            _e->SetKeyWithIV(key, key_len, iv, iv_len);
            //_fs = new FileSink(s, true);
            _fs = new FileSink(*fout_iv);
            //_fs->Put2(iv, iv_len, 1, false);
            _ef = new AuthenticatedEncryptionFilter(*_e, _fs, false, TAG_SIZE);
            _fbuf = new filebuf_ext(_ef);
        } else {
            _e = nullptr;
            _fs = nullptr;
            _ef = nullptr;
            _fbuf = new filebuf_ext();
        }
        this->init(_fbuf);
        this->open(s, mode);
    }

    ~ofstream_ext() {
        if (!_is_close) {
            this->close();
        }
        if (_e != nullptr) {
            //delete _e;
        }
        //delete _fbuf;
    }

    std::filebuf* rdbuf() const {
        return const_cast<filebuf_ext*>(_fbuf);
    }

    bool is_open() {
        return _fbuf->is_open();
    }

    bool is_open() const {
        return _fbuf->is_open();
    }

    void open(const char* s,
                std::ios_base::openmode mode = std::ios_base::out) {
        if (!_fbuf->open(s, mode | ios_base::out)) {
            this->setstate(ios_base::failbit);
        } else {
            this->clear();
        }
    }

    void open(const std::string& s,
                std::ios_base::openmode mode = std::ios_base::out) {
        if (!_fbuf->open(s, mode | ios_base::out)) {
            this->setstate(ios_base::failbit);
        } else {
            this->clear();
        }
    }

    void close() {
        _fbuf->post_process();
        _is_close = true;
        if (!_fbuf->close()) {
            this->setstate(ios_base::failbit);
        }
    }

private:
    filebuf_ext* _fbuf;
    GCM<AES>::Encryption* _e;
    AuthenticatedEncryptionFilter * _ef;
    FileSink* _fs;
    bool _is_close{false};

};

class ifstream_ext : public std::istream {
public:
    ifstream_ext() : std::istream(), _d(nullptr), _df(nullptr) {
        _fbuf = new filebuf_ext();
        this->init(_fbuf);
    }

    explicit ifstream_ext(const char* s,
                std::ios_base::openmode mode = std::ios_base::in) :
                std::istream(), _d(nullptr), _df(nullptr) {
        _fbuf = new filebuf_ext();
        this->init(_fbuf);
        this->open(s, mode);
    }

    explicit ifstream_ext(const char* s,
                std::ios_base::openmode mode,
                bool sec_enhanced,
                unsigned char* key_str,
                size_t key_len,
                unsigned char* iv_str,
                size_t iv_len,
                const int TAG_SIZE) :
                std::istream() {
        if (sec_enhanced) {
            std::ifstream if_mac(s, mode);
            
            SecByteBlock key(key_str, key_len);
            byte iv[iv_len];
            if_mac.read((char*) iv, iv_len);
            auto beg_pos = if_mac.tellg();
            //memcpy(iv, iv_str, iv_len);
            _d = new GCM<AES>::Decryption();
            _d->SetKeyWithIV(key, key_len, iv, iv_len);
            _df = new AuthenticatedDecryptionFilter(*_d, NULL,
                            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE);

            _fbuf = new filebuf_ext(_df, true);
            this->init(_fbuf);
            this->open(s, mode);

            
            this->seekg(0, std::ios::end);
            auto mac_pos = tellg() - (long int) TAG_SIZE;
            char mac[TAG_SIZE];
            //std::ifstream if_mac(s, mode);
            if_mac.seekg(mac_pos, std::ios::beg);
            if_mac.read(mac, TAG_SIZE);
            _df->ChannelPut(DEFAULT_CHANNEL, (const byte*) mac, TAG_SIZE);
            //if_mac.seekg(mac_pos, std::ios::beg);
            //if_mac.write(std::istream::traits_type::eof(), 1);
            seekg(beg_pos, std::ios::beg);

        } else {
            _d = nullptr;
            _fbuf = new filebuf_ext();
            this->init(_fbuf);
            this->open(s, mode);
        }
        
    }

    ~ifstream_ext() {
        if (!_is_close) {
            this->close();
        }
        if (_d != nullptr) {
            //delete _d;
        }
        //delete _fbuf;
    }

    std::filebuf* rdbuf() const {
        return const_cast<filebuf_ext*>(_fbuf);
    }

    bool is_open() {
        return _fbuf->is_open();
    }

    bool is_open() const {
        return _fbuf->is_open();
    }

    void open(const char* s, ios_base::openmode mode = ios_base::in) {
        if (!_fbuf->open(s, mode | ios_base::in)) {
            this->setstate(ios_base::failbit);
        } else {
            this->clear();
        }
    }

    void open(const std::string& s, ios_base::openmode mode = ios_base::in) {
        if (!_fbuf->open(s, mode | ios_base::in)) {
            this->setstate(ios_base::failbit);
        } else {
            this->clear();
        }
    }

    void close() {
        _fbuf->post_process();
        _is_close = true;
        if (!_fbuf->close()) {
            this->setstate(ios_base::failbit);
        }
    }
    

private:
    filebuf_ext* _fbuf;
    GCM<AES>::Decryption* _d;
    AuthenticatedDecryptionFilter* _df;
    bool _is_close{false};
};

}
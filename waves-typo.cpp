#include <windows.h>
#include <iostream>
#include <sstream>

#include <b58.c>

#include <botan\blake2b.h>
#include <botan\keccak.h>
#include <botan\sha2_32.h>
#pragma warning( push )
#pragma warning( disable : 4250 ) // inherits via dominance
#include <botan\curve25519.h>
#pragma warning( pop )

__declspec( align( 128 ) ) static uint8_t g_pubsechash[128];

struct waves_crypto
{
    waves_crypto() : _blake2b( 256 ), _keccak256( 256 ), _buf() {};

    auto sechash( uint8_t * data, size_t len )
    {
        _blake2b.update( data, len );
        _blake2b.final( _buf );
        _keccak256.update( _buf, 32 );
        _keccak256.final( _buf );
        return _buf;
    }

    auto pub( uint8_t * data, size_t len )
    {
        static const uint8_t _base9[32] = { 9 };

        _sha256.update( sechash( data, len ), 32 );
        _sha256.final( _buf );
        Botan::curve25519_donna( _buf, _buf, _base9 );
        return _buf;
    }

    auto pubsechash( uint8_t * data, size_t len )
    {
        return sechash( pub( data, len ), 32 );
    }

    Botan::Blake2b _blake2b;
    Botan::Keccak_1600 _keccak256;
    Botan::SHA_256 _sha256;
    uint8_t _buf[32];
};

static waves_crypto g_waves_crypto;
const char g_english[] = "abcdefghijklmnopqrstuvwxyz ";
char * g_seed;
size_t g_seed_len;

std::vector<std::string> seed_split( std::string str )
{
    std::istringstream split( str );
    std::vector<std::string> words;
    for( std::string word; std::getline( split, word, ' ' ); words.push_back( word ) );
    return words;
}

void seed_probe( uint8_t * seed, size_t len )
{
    if( 0 == memcmp( g_waves_crypto.pubsechash( seed, len ), g_pubsechash, 20 ) )
    {
        seed[len] = 0;
        std::cout << std::endl << "FOUND SEED = \"" << &seed[4] << "\"" << std::endl;
        ExitProcess( 0 );
    }
}

void set_pubsechash( char * address )
{
    uint8_t * buf = g_pubsechash;
    size_t len = sizeof( g_pubsechash );
    d58( address, strlen( address ), &buf, &len );

    if( buf[0] != 1 ||
        buf[1] != 'W' ||
        memcmp( &buf[22], g_waves_crypto.sechash( buf, 22 ), 4 ) )
    {
        std::cout << "Bad MAINNET address: " << address << std::endl;
        ExitProcess( 1 );
    }

    memmove( g_pubsechash, &buf[2], 20 );
}

int main( int argc, char ** argv )
{
    std::cout << "waves-typo (" << __DATE__ << ")" << std::endl;
    if( argc < 3 )
    {
        std::cout << "Usage: waves-typo.exe \"address\" \"seed\"" << std::endl;
        Sleep( 5000 );
        return 1;
    }

    set_pubsechash( argv[1] );
    g_seed = argv[2];
    g_seed_len = strlen( g_seed );

    uint8_t * seed = new uint8_t[g_seed_len + 4 + 2 + 32]();
    memcpy( &seed[4], g_seed, g_seed_len );
    seed_probe( seed, 4 + g_seed_len );

    auto words = seed_split( g_seed );

    // 1 WORD MISS
    std::cout << "1 WORD MISS... ";
    for( size_t i = 0; i < words.size(); i++ )
    {
        size_t s = 0;
        for( size_t j = 0; j < words.size(); j++ )
        {
            if( i == j )
                continue;

            if( s )
                seed[4 + s++] = ' ';

            memcpy( &seed[4 + s], &words[j][0], words[j].size() );
            s += words[j].size();
        }

        seed_probe( seed, 4 + s );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 2 WORDS MISS
    std::cout << "2 WORDS MISS... ";
    for( size_t i = 0; i < words.size(); i++ )
    for( size_t ii = i + 1; ii < words.size(); ii++ )
    {
        size_t s = 0;
        for( size_t j = 0; j < words.size(); j++ )
        {
            if( i == j || ii == j )
                continue;

            if( s )
                seed[4 + s++] = ' ';

            memcpy( &seed[4 + s], &words[j][0], words[j].size() );
            s += words[j].size();
        }

        seed_probe( seed, 4 + s );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 1 LETTER MISS
    std::cout << "1 LETTER MISS... ";
    for( size_t i = 1; i < g_seed_len; i++ )
    {
        memcpy( &seed[4 + g_seed_len - i - 1], &g_seed[g_seed_len - i], i );

        seed_probe( seed, 4 + g_seed_len - 1 );

        memcpy( &seed[4], g_seed, g_seed_len );
    }
    std::cout << "NO" << std::endl;

    // 2 LETTERS MISS
    std::cout << "2 LETTERS MISS... ";
    for( size_t i = 0; i < g_seed_len - 1; i++ )
    {
        memcpy( &seed[4 + i], &g_seed[i + 1], g_seed_len - i - 1 );

        for( size_t j = i; j < g_seed_len - 1; j++ )
        {
            memcpy( &seed[4 + j], &g_seed[j + 2], g_seed_len - j - 1 );

            seed_probe( seed, 4 + g_seed_len - 2 );

            memcpy( &seed[4 + i], &g_seed[i + 1], g_seed_len - i - 1 );
        }

        memcpy( &seed[4], g_seed, g_seed_len );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 1 WORD ADD
    std::cout << "1 WORD ADD... ";
    for( size_t i = 0; i < words.size() + 1; i++ )
    for( size_t k = 0; k < words.size(); k++ )
    {
        size_t s = 0;
        for( size_t j = 0; j < words.size(); j++ )
        {
            if( s )
                seed[4 + s++] = ' ';

            if( i == j )
            {
                memcpy( &seed[4 + s], &words[k][0], words[k].size() );
                s += words[k].size();
                seed[4 + s++] = ' ';
            }

            memcpy( &seed[4 + s], &words[j][0], words[j].size() );
            s += words[j].size();
        }

        if( i == words.size() )
        {
            seed[4 + s++] = ' ';
            memcpy( &seed[4 + s], &words[k][0], words[k].size() );
            s += words[k].size();
        }

        seed_probe( seed, 4 + s );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 1 LETTER ADD
    std::cout << "1 LETTER ADD... ";
    for( size_t i = 0; i < g_seed_len - 1; i++ )
    {
        memcpy( &seed[4 + g_seed_len - i], &g_seed[g_seed_len - i - 1], i + 1 );
        for( size_t j = 0; j < sizeof( g_english ) - 1; j++ )
        {
            seed[4 + g_seed_len - i - 1] = g_english[j];

            seed_probe( seed, 4 + g_seed_len + 1 );
        }
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 1 LETTER TYPO
    std::cout << "1 LETTER TYPO... ";
    for( size_t i = 0; i < g_seed_len; i++ )
    {
        char c = seed[4 + i];
        for( size_t j = 0; j < sizeof( g_english ) - 1; j++ )
        {
            seed[4 + i] = g_english[j];

            seed_probe( seed, 4 + g_seed_len );
        }
        seed[4 + i] = c;
    }
    std::cout << "NO" << std::endl;

    // 1 LETTER MISS + 1 LETTER TYPO
    std::cout << "1 LETTER MISS + 1 LETTER TYPO... " << g_seed_len - 1 << "... ";
    for( size_t i = 1; i < g_seed_len; i++ )
    {
        memcpy( &seed[4 + g_seed_len - i - 1], &g_seed[g_seed_len - i], i );

        for( size_t k = 0; k < g_seed_len - 1; k++ )
        {
            char c2 = seed[4 + k];
            for( size_t m = 0; m < sizeof( g_english ) - 1; m++ )
            {
                seed[4 + k] = g_english[m];

                seed_probe( seed, 4 + g_seed_len - 1 );
            }
            seed[4 + k] = c2;
        }

        std::cout << g_seed_len - i - 1 << "... ";
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 2 LETTERS TYPO
    std::cout << "2 LETTERS TYPO... " << g_seed_len << "... ";
    for( size_t i = 0; i < g_seed_len; i++ )
    {
        char c1 = seed[4 + i];
        for( size_t j = 0; j < sizeof( g_english ) - 1; j++ )
        {
            seed[4 + i] = g_english[j];

            for( size_t k = i + 1; k < g_seed_len; k++ )
            {
                char c2 = seed[4 + k];
                for( size_t m = 0; m < sizeof( g_english ) - 1; m++ )
                {
                    seed[4 + k] = g_english[m];

                    seed_probe( seed, 4 + g_seed_len );
                }
                seed[4 + k] = c2;
            }
        }
        seed[4 + i] = c1;

        std::cout << g_seed_len - i - 1 << "... ";
    }
    std::cout << "NO" << std::endl;

    // 1 LETTER ADD + 1 LETTER TYPO
    std::cout << "1 LETTER ADD + 1 LETTER TYPO... " << g_seed_len - 1 << "... ";
    for( size_t i = 0; i < g_seed_len - 1; i++ )
    {
        memcpy( &seed[4 + g_seed_len - i], &g_seed[g_seed_len - i - 1], i + 1 );
        for( size_t j = 0; j < sizeof( g_english ) - 1; j++ )
        {
            seed[4 + g_seed_len - i - 1] = g_english[j];

            for( size_t k = 0; k < g_seed_len + 1; k++ )
            {
                char c2 = seed[4 + k];
                for( size_t m = 0; m < sizeof( g_english ) - 1; m++ )
                {
                    seed[4 + k] = g_english[m];

                    seed_probe( seed, 4 + g_seed_len + 1 );
                }
                seed[4 + k] = c2;
            }
        }

        std::cout << g_seed_len - i - 2 << "... ";
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    std::cout << "NOT FOUND" << std::endl;
    return 1;
}

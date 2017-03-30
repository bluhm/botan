/*
* System Call getentropy(2)
* (C) 2017 Alexander Bluhm (genua GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/getentropy.h>

#include <string.h>
#include <unistd.h>

namespace Botan {

/**
* Getentropy constructor
* Check that getentropy(2) works as expected.  On OpenBSD it may only
* fail if the data pointer is invalid or size exceeds 256 bytes.
*/
Getentropy::Getentropy()
   {
   secure_vector<uint8_t> buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);
   uint8_t *data = buf.data();
   size_t size = buf.size();

   ::memset(data, 0, size);
   if(::getentropy(data, size) != 0)
      {
      throw Exception("Call getentropy() failed: " + std::string(::strerror(errno)));
      }
   for(size_t i = 0; i < size; i++)
      {
      if(data[i] != 0)
         {
         return;
         }
      }
   throw Exception("After getentropy() data is zero");
   }

/**
* Gather BOTAN_SYSTEM_RNG_POLL_REQUEST bytes entropy from getentropy(2).
* This is 64 bytes, note that maximum buffer size is limited to 256 bytes.
*/
size_t Getentropy::poll(RandomNumberGenerator& rng)
   {
   secure_vector<uint8_t> buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);

   if(::getentropy(buf.data(), buf.size()) == 0)
      {
      rng.add_entropy(buf.data(), buf.size());
      return buf.size() * 8;
      }

   return 0;
   }
}

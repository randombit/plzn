// Copyright 2014 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PLZN_BORINGSSL_PACKETED_BIO_H_
#define PLZN_BORINGSSL_PACKETED_BIO_H_

#include <cstdint>

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <sys/time.h>

// This is BoringSSL's ssl/test PacketedBio adapted to plzn's packet protocol.
// In particular, plzn requires an acknowledgement after E, U, and M controls so
// the runner knows that the deferred operation has completed successfully.
bssl::UniquePtr<BIO> PacketedBioCreate(timeval* clock, SSL* ssl);
bool PacketedBioHasInterrupt(BIO* bio);
bool PacketedBioHandleInterrupt(BIO* bio);
bool PacketedBioAdvanceClock(BIO* bio, uint64_t microseconds);

#endif

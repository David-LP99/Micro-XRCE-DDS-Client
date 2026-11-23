// Copyright 2026 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * Regression tests for malformed input reaching the session receive path.
 * Each test feeds a crafted datagram (or a crafted buffer) to the code the Agent's traffic goes through,
 * and checks that the Client neither hangs nor crashes.
 */

extern "C"
{
#include <c/core/serialization/xrce_types.c>
#include <c/core/serialization/xrce_header.c>
#include <c/core/serialization/xrce_subheader.c>

#include <c/core/session/stream/seq_num.c>
#include <c/core/session/stream/stream_id.c>
#include <c/core/session/stream/stream_storage.c>
#include <c/core/session/stream/input_best_effort_stream.c>
#include <c/core/session/stream/output_best_effort_stream.c>
#include <c/core/session/stream/input_reliable_stream.c>
#include <c/core/session/stream/output_reliable_stream.c>

#include <c/core/session/object_id.c>
#include <c/core/session/submessage.c>
#include <c/core/session/session_info.c>
#include <c/core/session/read_access.c>
#include <c/core/session/write_access.c>

#include <c/util/time.c>

#undef UXR_MESSAGE_LOG
#undef UXR_SERIALIZATION_LOG
#include <c/core/session/session.c>
}

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <vector>

#define MTU     64
#define HISTORY 4

class MalformedInputTest : public testing::Test
{
protected:

    MalformedInputTest()
    {
        comm.instance = this;
        comm.mtu = MTU;
        comm.send_msg = send_msg;
        comm.recv_msg = recv_msg;
        comm.comm_error = comm_error;

        uxr_init_session(&session, &comm, 0xAAAABBBB);  // session id 0x81, no client key on the wire
        session.on_pong_flag = NO_PONG_STATUS;

        (void) uxr_create_input_best_effort_stream(&session);
        (void) uxr_create_input_reliable_stream(&session, input_reliable_buffer, MTU * HISTORY, HISTORY);
    }

    /*
     * Hands a datagram to the session as if the transport had just received it.
     */
    void feed(
            std::vector<uint8_t> datagram)
    {
        ucdrBuffer ub;
        ucdr_init_buffer(&ub, datagram.data(), datagram.size());
        read_message(&session, &ub);
    }

    // Helpers needed since uxrCommunication holds function pointers.
    static bool send_msg(
            void* instance,
            const uint8_t* buf,
            size_t len)
    {
        (void) buf; (void) len;
        static_cast<MalformedInputTest*>(instance)->sent_messages++;
        return true;
    }

    static bool recv_msg(
            void* instance,
            uint8_t** buf,
            size_t* len,
            int timeout)
    {
        (void) instance; (void) buf; (void) len; (void) timeout;
        return false;
    }

    static uint8_t comm_error(
            void)
    {
        return 0u;
    }

    uxrCommunication comm;
    uxrSession session;
    uint8_t input_reliable_buffer[MTU * HISTORY];
    int sent_messages = 0;
};

/*
 * GHSA-xg64-g72v-chxr: the 37-byte message from the advisory, verbatim.
 *
 * 81 00 00 00   header: session 0x81, stream 0x00 (none), sequence 0
 * 06 32 04 01   INFO submessage, big-endian payload
 * ...           BaseObjectReply, optional_config, kind PARTICIPANT, format BY_REFERENCE,
 *               then a string length of 0x2500, larger than UXR_STRING_SIZE_MAX
 *
 * The oversized string length puts the buffer in error with bytes still left after it.
 * The submessage loop must stop there instead of dispatching the same submessage forever.
 */
TEST_F(MalformedInputTest, AdvisoryPocTerminates)
{
    const std::vector<uint8_t> poc = {
        0x81, 0x00, 0x00, 0x00, 0x06, 0x32, 0x04, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x0b, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };
    ASSERT_EQ(37u, poc.size());

    // Before the fix this never returns. A looping thread can't be stopped, so exit the process on timeout.
    std::future<void> done = std::async(std::launch::async, [this, &poc]()
                    {
                        feed(poc);
                    });
    if (std::future_status::ready != done.wait_for(std::chrono::seconds(5)))
    {
        std::fprintf(stderr, "AdvisoryPocTerminates: did not return within 5 s, the receive path is looping\n");
        std::fflush(stderr);
        std::_Exit(EXIT_FAILURE);
    }
}

/*
 * GHSA-xg64-g72v-chxr, root cause on its own: once the buffer is in error, no further submessage
 * header can be read from it, however many bytes remain.
 */
TEST_F(MalformedInputTest, SubmessageHeaderStopsOnBufferError)
{
    std::array<uint8_t, 8> bytes = {};
    ucdrBuffer ub;
    ucdr_init_buffer(&ub, bytes.data(), bytes.size());
    ub.error = true;

    uint8_t id = 0;
    uint16_t length = 0;
    uint8_t flags = 0;
    EXPECT_FALSE(uxr_read_submessage_header(&ub, &id, &length, &flags));
}

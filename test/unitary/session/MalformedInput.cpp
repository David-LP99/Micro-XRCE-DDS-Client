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
#include <cstring>
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

/*
 * GHSA-2cmh-jh56-mpjm: the string members of these types are bare `char*`, and the caller must point
 * them at storage before decoding. The receive paths that decode INFO have no storage for strings,
 * so a NULL target must make the decode fail instead of copying the string through it.
 *
 * The ObjectVariant buffers below follow the description: a config of a kind other than AGENT, in a
 * string representation. All of them are little endian and start at offset 0, so CDR alignment is
 * relative to the kind byte.
 */
static std::vector<uint8_t> participant_with_string(
        uint8_t format)
{
    return {
        0x01,                       // kind: DDS_XRCE_OBJK_PARTICIPANT
        format,                     // representation format
        0x00, 0x00,                 // alignment padding
        0x04, 0x00, 0x00, 0x00,     // string length 4
        'r', 'e', 'f', 0x00,        // "ref"
        0x00, 0x00                  // domain_id 0
    };
}

static ucdrBuffer little_endian_buffer(
        std::vector<uint8_t>& bytes)
{
    ucdrBuffer ub;
    ucdr_init_buffer(&ub, bytes.data(), bytes.size());
    ub.endianness = UCDR_LITTLE_ENDIANNESS;
    return ub;
}

TEST_F(MalformedInputTest, ObjectVariantParticipantByReferenceNullTarget)
{
    std::vector<uint8_t> bytes = participant_with_string(DDS_XRCE_REPRESENTATION_BY_REFERENCE);
    ucdrBuffer ub = little_endian_buffer(bytes);

    ObjectVariant variant;
    std::memset(&variant, 0, sizeof(variant));
    variant._.participant.base.representation._.object_reference = nullptr;

    EXPECT_FALSE(uxr_deserialize_ObjectVariant(&ub, &variant));
    EXPECT_TRUE(ucdr_buffer_has_error(&ub));
}

TEST_F(MalformedInputTest, ObjectVariantParticipantXmlNullTarget)
{
    std::vector<uint8_t> bytes = participant_with_string(DDS_XRCE_REPRESENTATION_AS_XML_STRING);
    ucdrBuffer ub = little_endian_buffer(bytes);

    ObjectVariant variant;
    std::memset(&variant, 0, sizeof(variant));
    variant._.participant.base.representation._.xml_string_represenatation = nullptr;

    EXPECT_FALSE(uxr_deserialize_ObjectVariant(&ub, &variant));
    EXPECT_TRUE(ucdr_buffer_has_error(&ub));
}

TEST_F(MalformedInputTest, ObjectVariantApplicationNullTarget)
{
    std::vector<uint8_t> bytes = {
        0x0C,                       // kind: DDS_XRCE_OBJK_APPLICATION (RefAndXML representation)
        0x01,                       // format: DDS_XRCE_REPRESENTATION_BY_REFERENCE
        0x00, 0x00,                 // alignment padding
        0x04, 0x00, 0x00, 0x00,     // string length 4
        'r', 'e', 'f', 0x00         // "ref"
    };
    ucdrBuffer ub = little_endian_buffer(bytes);

    ObjectVariant variant;
    std::memset(&variant, 0, sizeof(variant));
    variant._.application.base.representation._.object_name = nullptr;

    EXPECT_FALSE(uxr_deserialize_ObjectVariant(&ub, &variant));
    EXPECT_TRUE(ucdr_buffer_has_error(&ub));
}

TEST_F(MalformedInputTest, ObjectVariantPublisherStringNullTarget)
{
    std::vector<uint8_t> bytes = {
        0x03,                       // kind: DDS_XRCE_OBJK_PUBLISHER (BinAndXML representation)
        0x02,                       // format: DDS_XRCE_REPRESENTATION_AS_XML_STRING
        0x00, 0x00,                 // alignment padding
        0x04, 0x00, 0x00, 0x00,     // string length 4
        'r', 'e', 'f', 0x00,        // "ref"
        0x00, 0x01                  // participant_id
    };
    ucdrBuffer ub = little_endian_buffer(bytes);

    ObjectVariant variant;
    std::memset(&variant, 0, sizeof(variant));
    variant._.publisher.base.representation._.string_represenatation = nullptr;

    EXPECT_FALSE(uxr_deserialize_ObjectVariant(&ub, &variant));
    EXPECT_TRUE(ucdr_buffer_has_error(&ub));
}

TEST_F(MalformedInputTest, ObjectVariantClientPropertyNullTarget)
{
    std::vector<uint8_t> bytes = {
        0x0E,                       // kind: DDS_XRCE_OBJK_CLIENT
        'X', 'R', 'C', 'E',         // xrce_cookie
        0x01, 0x00,                 // xrce_version
        0x01, 0x0F,                 // xrce_vendor_id
        0xAA, 0xBB, 0xCC, 0xDD,     // client_key
        0x81,                       // session_id
        0x01,                       // optional_properties: present
        0x00,                       // alignment padding
        0x01, 0x00, 0x00, 0x00,     // properties: 1 element
        0x02, 0x00, 0x00, 0x00,     // name: length 2
        'a', 0x00,                  // "a"
        0x00, 0x00,                 // alignment padding
        0x02, 0x00, 0x00, 0x00,     // value: length 2
        'b', 0x00,                  // "b"
        0x00, 0x02                  // mtu 512
    };
    ucdrBuffer ub = little_endian_buffer(bytes);

    ObjectVariant variant;
    std::memset(&variant, 0, sizeof(variant));
    variant._.client.properties.data[0].name = nullptr;
    variant._.client.properties.data[0].value = nullptr;

    EXPECT_FALSE(uxr_deserialize_ObjectVariant(&ub, &variant));
    EXPECT_TRUE(ucdr_buffer_has_error(&ub));
}

/*
 * The same applies outside ObjectVariant: each address in an INFO's AGENT activity is a TransportLocator,
 * and the STRING format decodes into a bare `char*`. Discovery and the message logger decode these
 * addresses from received INFO messages.
 */
TEST_F(MalformedInputTest, TransportLocatorStringNullTarget)
{
    std::vector<uint8_t> bytes = {
        0x03,                       // format: ADDRESS_FORMAT_STRING
        0x00, 0x00, 0x00,           // alignment padding
        0x0A, 0x00, 0x00, 0x00,     // string length 10
        '1', '2', '7', '.', '0', '.', '0', '.', '1', 0x00     // "127.0.0.1"
    };
    ucdrBuffer ub = little_endian_buffer(bytes);

    TransportLocator locator;
    std::memset(&locator, 0, sizeof(locator));
    locator._.string_locator.value = nullptr;

    EXPECT_FALSE(uxr_deserialize_TransportLocator(&ub, &locator));
    EXPECT_TRUE(ucdr_buffer_has_error(&ub));
}

/*
 * Guard: a caller that does point the string at storage, as the message logger does for the Client's
 * own CREATE messages, must keep decoding it.
 */
TEST_F(MalformedInputTest, ObjectVariantWithStorageDecodes)
{
    std::vector<uint8_t> bytes = participant_with_string(DDS_XRCE_REPRESENTATION_BY_REFERENCE);
    ucdrBuffer ub = little_endian_buffer(bytes);

    char storage[UXR_STRING_SIZE_MAX];
    ObjectVariant variant;
    std::memset(&variant, 0, sizeof(variant));
    variant._.participant.base.representation._.object_reference = storage;

    EXPECT_TRUE(uxr_deserialize_ObjectVariant(&ub, &variant));
    EXPECT_FALSE(ucdr_buffer_has_error(&ub));
    EXPECT_STREQ("ref", storage);
}

/*
 * Guard: an INFO as a real Agent sends it (AGENT config, no properties, AGENT activity) must still
 * be processed: availability 1 in an active session sets the pong flag.
 */
TEST_F(MalformedInputTest, InfoFromRealAgentStillPongs)
{
    const std::vector<uint8_t> datagram = {
        0x81, 0x00, 0x00, 0x00,     // header: session 0x81, stream 0x00 (none), sequence 0
        0x06, 0x01, 0x1C, 0x00,     // INFO submessage, little endian, length 28
        0x00, 0x00, 0x00, 0x00,     // related_request: request_id, object_id
        0x00, 0x01,                 // result: STATUS_OK, implementation_status 1 (active session)
        0x01,                       // optional_config: present
        0x0D,                       // kind: DDS_XRCE_OBJK_AGENT
        'X', 'R', 'C', 'E',         // xrce_cookie
        0x01, 0x00,                 // xrce_version
        0x01, 0x0F,                 // xrce_vendor_id
        0x00,                       // optional_properties: absent
        0x01,                       // optional_activity: present
        0x0D,                       // activity kind: DDS_XRCE_OBJK_AGENT
        0x00,                       // alignment padding
        0x01, 0x00,                 // availability 1
        0x00, 0x00,                 // alignment padding
        0x00, 0x00, 0x00, 0x00      // address_seq: empty
    };

    feed(datagram);

    EXPECT_EQ(PONG_IN_SESSION_STATUS, session.on_pong_flag);
}

/*
 * GHSA-2cmh-jh56-mpjm, through the receive path: the same INFO, but with a PARTICIPANT config whose
 * representation is a string. The INFO must be rejected without touching memory, so the AGENT
 * activity that follows is never processed and the pong flag stays unset.
 */
TEST_F(MalformedInputTest, InfoWithNonAgentConfigIsRejected)
{
    const std::vector<uint8_t> datagram = {
        0x81, 0x00, 0x00, 0x00,     // header: session 0x81, stream 0x00 (none), sequence 0
        0x06, 0x01, 0x20, 0x00,     // INFO submessage, little endian, length 32
        0x00, 0x00, 0x00, 0x00,     // related_request: request_id, object_id
        0x00, 0x01,                 // result: STATUS_OK, implementation_status 1 (active session)
        0x01,                       // optional_config: present
        0x01,                       // kind: DDS_XRCE_OBJK_PARTICIPANT
        0x01,                       // format: DDS_XRCE_REPRESENTATION_BY_REFERENCE
        0x00, 0x00, 0x00,           // alignment padding
        0x04, 0x00, 0x00, 0x00,     // string length 4
        'r', 'e', 'f', 0x00,        // "ref"
        0x00, 0x00,                 // domain_id 0
        0x01,                       // optional_activity: present
        0x0D,                       // activity kind: DDS_XRCE_OBJK_AGENT
        0x01, 0x00,                 // availability 1
        0x00, 0x00,                 // alignment padding
        0x00, 0x00, 0x00, 0x00      // address_seq: empty
    };

    feed(datagram);

    EXPECT_EQ(NO_PONG_STATUS, session.on_pong_flag);
}

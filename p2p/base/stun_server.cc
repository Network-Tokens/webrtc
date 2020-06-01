/*
 *  Copyright 2004 The WebRTC Project Authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include "p2p/base/stun_server.h"

#include <utility>

#include "rtc_base/byte_buffer.h"
#include "rtc_base/logging.h"

enum TokenReflectType {
  TokenOrigin        = 0x0,
  TokenOriginReflect = 0x1,
  TokenReflected     = 0x2,
};

namespace cricket {

StunServer::StunServer(rtc::AsyncUDPSocket* socket) : socket_(socket) {
  socket_->SignalReadPacket.connect(this, &StunServer::OnPacket);
}

StunServer::~StunServer() {
  socket_->SignalReadPacket.disconnect(this);
}

void StunServer::OnPacket(rtc::AsyncPacketSocket* socket,
                          const char* buf,
                          size_t size,
                          const rtc::SocketAddress& remote_addr,
                          const int64_t& /* packet_time_us */) {
  // Parse the STUN message; eat any messages that fail to parse.
  rtc::ByteBufferReader bbuf(buf, size);
  StunMessage msg;
  if (!msg.Read(&bbuf)) {
    return;
  }

  // TODO(?): If unknown non-optional (<= 0x7fff) attributes are found, send a
  //          420 "Unknown Attribute" response.

  // Send the message to the appropriate handler function.
  switch (msg.type()) {
    case STUN_BINDING_REQUEST:
      OnBindingRequest(&msg, remote_addr);
      break;

    default:
      SendErrorResponse(msg, remote_addr, 600, "Operation Not Supported");
  }
}

void StunServer::OnBindingRequest(StunMessage* msg,
                                  const rtc::SocketAddress& remote_addr) {
  StunMessage response;
  GetStunBindResponse(msg, remote_addr, &response);
  SendResponse(response, remote_addr);
}

void StunServer::SendErrorResponse(const StunMessage& msg,
                                   const rtc::SocketAddress& addr,
                                   int error_code,
                                   const char* error_desc) {
  StunMessage err_msg;
  err_msg.SetType(GetStunErrorResponseType(msg.type()));
  err_msg.SetTransactionID(msg.transaction_id());

  auto err_code = StunAttribute::CreateErrorCode();
  err_code->SetCode(error_code);
  err_code->SetReason(error_desc);
  err_msg.AddAttribute(std::move(err_code));

  SendResponse(err_msg, addr);
}

void StunServer::SendResponse(const StunMessage& msg,
                              const rtc::SocketAddress& addr) {
  rtc::ByteBufferWriter buf;
  msg.Write(&buf);
  rtc::PacketOptions options;
  if (socket_->SendTo(buf.Data(), buf.Length(), addr, options) < 0)
    RTC_LOG_ERR(LS_ERROR) << "sendto";
}

void StunServer::GetStunBindResponse(StunMessage* request,
                                     const rtc::SocketAddress& remote_addr,
                                     StunMessage* response) const {
  response->SetType(STUN_BINDING_RESPONSE);
  response->SetTransactionID(request->transaction_id());

  // Tell the user the address that we received their request from.
  std::unique_ptr<StunAddressAttribute> mapped_addr;
  if (request->IsLegacy()) {
    mapped_addr = StunAttribute::CreateAddress(STUN_ATTR_MAPPED_ADDRESS);
  } else {
    mapped_addr = StunAttribute::CreateXorAddress(STUN_ATTR_XOR_MAPPED_ADDRESS);
  }

  // If there is a network token attribute present on the STUN request, reflect
  // this on the STUN response.
  const StunAttribute* token_attr = request->GetByteString(
      STUN_ATTR_NETWORK_TOKEN);
  if(token_attr) {
    std::string token(token_attr->GetString());
    int reflect = (token.size() ? token[0] : 0) >> 4;
    if(reflect == TokenOriginReflect) {
      token[0] = (TokenReflected << 4) | (token[0] & 0xF);
      response->AddAttribute(absl::make_unique<StunByteStringAttribute>(
          STUN_ATTR_NETWORK_TOKEN, token));
    }
  }

  mapped_addr->SetAddress(remote_addr);
  response->AddAttribute(std::move(mapped_addr));
}

}  // namespace cricket

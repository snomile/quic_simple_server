// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/tools/quic_simple_server_session.h"

#include <utility>

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_session.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/tools/quic_simple_server_stream.h"


namespace quic {

QuicSimpleServerSession::QuicSimpleServerSession(
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection,
    QuicSession::Visitor* visitor,
    QuicCryptoServerStream::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    QuicSimpleServerBackend* quic_simple_server_backend)
    : QuicServerSessionBase(config,
                            supported_versions,
                            connection,
                            visitor,
                            helper,
                            crypto_config,
                            compressed_certs_cache),
      highest_promised_stream_id_(
          QuicUtils::GetInvalidStreamId(connection->transport_version())),
      quic_simple_server_backend_(quic_simple_server_backend) {
  DCHECK(quic_simple_server_backend_);
  setConnectionLogger();
}

QuicSimpleServerSession::~QuicSimpleServerSession() {
    netlogWithSource.EndEvent(net::NetLogEventType::QUIC_SESSION);
    net_log_file_observer_->StopObserving(nullptr,base::OnceClosure());
    net_log_file_observer_.reset();
    delete netlogWithSource.net_log();
    connection()->set_debug_visitor(nullptr);
    std::cout <<"mod:QuicSimpleServerSession::~QuicSimpleServerSession:finished" << std::endl;
    DeleteConnection();
}


base::FilePath QuicSimpleServerSession::getNetLogName(){
   //time
    time_t nowtime;
    nowtime = time(NULL); //获取日历时间
    struct tm *local;
    local=localtime(&nowtime);  //获取当前系统时间
    char buf[80];
    strftime(buf,80,"%Y-%m-%d_%H:%M:%S_",local);
    std::string time_str(buf);

    QuicConnectionId server_connection_id_ = connection_id();
    std::string server_connection_id_str = server_connection_id_.ToString();
    std::string file_name = "netlog_"+ time_str + server_connection_id_str + ".json";
    base::FilePath file_path(file_name);

    return file_path;
}


void QuicSimpleServerSession::setConnectionLogger(){
    //net::NetLog* net_log = net::NetLog::Get();  //如果使用单例的netlog，会使得不同connection的net_log_file_observer_被加入到同一个netlog中，导致重复记录日志
    net::NetLog* net_log = new net::NetLog(0);
    netlogWithSource = net::NetLogWithSource::Make(net_log, net::NetLogSourceType::QUIC_SESSION);

    logger_ = new net::QuicConnectionLogger(this, "connection_description here", /*std::move(socket_performance_watcher)*/nullptr,netlogWithSource);
    connection()->set_debug_visitor(logger_);
    connection()->set_creator_debug_delegate(logger_);

    base::FilePath file_path = getNetLogName();
    net_log_file_observer_ = net::FileNetLogObserver::CreateUnbounded(file_path, /*constants=*/nullptr);
    net::NetLogCaptureMode capture_mode = net::NetLogCaptureMode::kDefault;
    net_log_file_observer_->StartObserving(net_log, capture_mode);
     
    std::cout <<"mod:QuicSimpleServerSession::setConnectionLogger:set debug visitor finished" << std::endl;
}

void QuicSimpleServerSession::OnCryptoHandshakeMessageSent(
    const quic::CryptoHandshakeMessage& message) {
  logger_->OnCryptoHandshakeMessageSent(message);
}

void QuicSimpleServerSession::OnCryptoHandshakeMessageReceived(
    const quic::CryptoHandshakeMessage& message) {
  //setConnectionLogger();
  logger_->OnCryptoHandshakeMessageReceived(message);
}
 
void QuicSimpleServerSession::OnHeaderList(const QuicHeaderList& header_list) {
  

  /*
  logger_.AddEvent(
      NetLogEventType::HTTP_TRANSACTION_READ_HEADERS,   //BIDIRECTIONAL_STREAM_RECV_HEADERS
      "headers", "Received header list for stream " << stream_id_ << ": " << header_list.DebugString() );


  netlogWithSource.AddEvent(net::NetLogEventType::BIDIRECTIONAL_STREAM_RECV_HEADERS,
                    [&](net::NetLogCaptureMode capture_mode) {
                      return NetLogHeadersParams(&header_list,
                                                  capture_mode);
                    });
  */

  netlogWithSource.AddEventWithStringParams(net::NetLogEventType::QUIC_SIMPLE_SERVER_SESSION_RECEIVED_HEADERS,
                                "header",
                                header_list.DebugString());


  QuicSpdySession::OnHeaderList(header_list);
}                                




std::unique_ptr<QuicCryptoServerStreamBase>
QuicSimpleServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache) {
  return CreateCryptoServerStream(crypto_config, compressed_certs_cache, this,
                                  stream_helper());
}

void QuicSimpleServerSession::OnStreamFrame(const QuicStreamFrame& frame) {
  if (!IsIncomingStream(frame.stream_id)) {
    QUIC_LOG(WARNING) << "Client shouldn't send data on server push stream";
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Client sent data on server push stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  QuicSpdySession::OnStreamFrame(frame);
}

void QuicSimpleServerSession::PromisePushResources(
    const std::string& request_url,
    const std::list<QuicBackendResponse::ServerPushInfo>& resources,
    QuicStreamId original_stream_id,
    const spdy::SpdyStreamPrecedence& original_precedence,
    const spdy::SpdyHeaderBlock& original_request_headers) {
  if (!server_push_enabled()) {
    return;
  }

  for (QuicBackendResponse::ServerPushInfo resource : resources) {
    spdy::SpdyHeaderBlock headers = SynthesizePushRequestHeaders(
        request_url, resource, original_request_headers);
    highest_promised_stream_id_ +=
        QuicUtils::StreamIdDelta(transport_version());
    if (VersionUsesHttp3(transport_version()) &&
        highest_promised_stream_id_ > max_allowed_push_id()) {
      return;
    }
    SendPushPromise(original_stream_id, highest_promised_stream_id_,
                    headers.Clone());
    promised_streams_.push_back(PromisedStreamInfo(
        std::move(headers), highest_promised_stream_id_,
        use_http2_priority_write_scheduler()
            ? original_precedence
            : spdy::SpdyStreamPrecedence(resource.priority)));
  }

  // Procese promised push request as many as possible.
  HandlePromisedPushRequests();
}

QuicSpdyStream* QuicSimpleServerSession::CreateIncomingStream(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicSpdyStream* stream = new QuicSimpleServerStream(
      id, this, BIDIRECTIONAL, quic_simple_server_backend_);
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

QuicSpdyStream* QuicSimpleServerSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicSpdyStream* stream = new QuicSimpleServerStream(
      pending, this, BIDIRECTIONAL, quic_simple_server_backend_);
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

QuicSimpleServerStream*
QuicSimpleServerSession::CreateOutgoingBidirectionalStream() {
  DCHECK(false);
  return nullptr;
}

QuicSimpleServerStream*
QuicSimpleServerSession::CreateOutgoingUnidirectionalStream() {
  if (!ShouldCreateOutgoingUnidirectionalStream()) {
    return nullptr;
  }

  QuicSimpleServerStream* stream = new QuicSimpleServerStream(
      GetNextOutgoingUnidirectionalStreamId(), this, WRITE_UNIDIRECTIONAL,
      quic_simple_server_backend_);
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

void QuicSimpleServerSession::HandleFrameOnNonexistentOutgoingStream(
    QuicStreamId stream_id) {
  // If this stream is a promised but not created stream (stream_id within the
  // range of next_outgoing_stream_id_ and highes_promised_stream_id_),
  // connection shouldn't be closed.
  // Otherwise behave in the same way as base class.
  if (highest_promised_stream_id_ ==
          QuicUtils::GetInvalidStreamId(transport_version()) ||
      stream_id > highest_promised_stream_id_) {
    QuicSession::HandleFrameOnNonexistentOutgoingStream(stream_id);
  }
}

void QuicSimpleServerSession::HandleRstOnValidNonexistentStream(
    const QuicRstStreamFrame& frame) {
  QuicSession::HandleRstOnValidNonexistentStream(frame);
  if (!IsClosedStream(frame.stream_id)) {
    // If a nonexistent stream is not a closed stream and still valid, it must
    // be a locally preserved stream. Resetting this kind of stream means
    // cancelling the promised server push.
    // Since PromisedStreamInfo are queued in sequence, the corresponding
    // index for it in promised_streams_ can be calculated.
    QuicStreamId next_stream_id = next_outgoing_unidirectional_stream_id();
    if (VersionHasIetfQuicFrames(transport_version())) {
      DCHECK(!QuicUtils::IsBidirectionalStreamId(frame.stream_id));
    }
    DCHECK_GE(frame.stream_id, next_stream_id);
    size_t index = (frame.stream_id - next_stream_id) /
                   QuicUtils::StreamIdDelta(transport_version());
    DCHECK_LE(index, promised_streams_.size());
    promised_streams_[index].is_cancelled = true;
    control_frame_manager().WriteOrBufferRstStream(frame.stream_id,
                                                   QUIC_RST_ACKNOWLEDGEMENT, 0);
    connection()->OnStreamReset(frame.stream_id, QUIC_RST_ACKNOWLEDGEMENT);
  }
}

spdy::SpdyHeaderBlock QuicSimpleServerSession::SynthesizePushRequestHeaders(
    std::string request_url,
    QuicBackendResponse::ServerPushInfo resource,
    const spdy::SpdyHeaderBlock& original_request_headers) {
  QuicUrl push_request_url = resource.request_url;

  spdy::SpdyHeaderBlock spdy_headers = original_request_headers.Clone();
  // :authority could be different from original request.
  spdy_headers[":authority"] = push_request_url.host();
  spdy_headers[":path"] = push_request_url.path();
  // Push request always use GET.
  spdy_headers[":method"] = "GET";
  spdy_headers["referer"] = request_url;
  spdy_headers[":scheme"] = push_request_url.scheme();
  // It is not possible to push a response to a request that includes a request
  // body.
  spdy_headers["content-length"] = "0";
  // Remove "host" field as push request is a directly generated HTTP2 request
  // which should use ":authority" instead of "host".
  spdy_headers.erase("host");
  return spdy_headers;
}

void QuicSimpleServerSession::SendPushPromise(QuicStreamId original_stream_id,
                                              QuicStreamId promised_stream_id,
                                              spdy::SpdyHeaderBlock headers) {
  QUIC_DLOG(INFO) << "stream " << original_stream_id
                  << " send PUSH_PROMISE for promised stream "
                  << promised_stream_id;
  WritePushPromise(original_stream_id, promised_stream_id, std::move(headers));
}

void QuicSimpleServerSession::HandlePromisedPushRequests() {
  while (!promised_streams_.empty() &&
         ShouldCreateOutgoingUnidirectionalStream()) {
    PromisedStreamInfo& promised_info = promised_streams_.front();
    DCHECK_EQ(next_outgoing_unidirectional_stream_id(),
              promised_info.stream_id);

    if (promised_info.is_cancelled) {
      // This stream has been reset by client. Skip this stream id.
      promised_streams_.pop_front();
      GetNextOutgoingUnidirectionalStreamId();
      return;
    }

    QuicSimpleServerStream* promised_stream =
        static_cast<QuicSimpleServerStream*>(
            CreateOutgoingUnidirectionalStream());
    DCHECK_NE(promised_stream, nullptr);
    DCHECK_EQ(promised_info.stream_id, promised_stream->id());
    QUIC_DLOG(INFO) << "created server push stream " << promised_stream->id();

    promised_stream->SetPriority(promised_info.precedence);

    spdy::SpdyHeaderBlock request_headers(
        std::move(promised_info.request_headers));

    promised_streams_.pop_front();
    promised_stream->PushResponse(std::move(request_headers));
  }
}

void QuicSimpleServerSession::OnCanCreateNewOutgoingStream(
    bool unidirectional) {
  QuicSpdySession::OnCanCreateNewOutgoingStream(unidirectional);
  if (unidirectional) {
    HandlePromisedPushRequests();
  }
}

void QuicSimpleServerSession::MaybeInitializeHttp3UnidirectionalStreams() {
  size_t previous_static_stream_count = num_outgoing_static_streams();
  QuicSpdySession::MaybeInitializeHttp3UnidirectionalStreams();
  size_t current_static_stream_count = num_outgoing_static_streams();
  DCHECK_GE(current_static_stream_count, previous_static_stream_count);
  highest_promised_stream_id_ +=
      QuicUtils::StreamIdDelta(transport_version()) *
      (current_static_stream_count - previous_static_stream_count);
}
}  // namespace quic

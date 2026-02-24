#include "h264_sei_parser.h"

#include <stdio.h>

#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <memory>
#include <vector>
#include <array>

#include "h264_common.h"
#include "h264_vui_parameters_parser.h"
#include "h264_bitstream_parser_state.h"
#include "h264_sps_parser.h"

namespace h264nal {

H264SeiDataParser::SeiDataState::SeiDataState(uint32_t _payloadType, uint32_t _payloadSize)
  : payloadType(_payloadType), payloadSize(_payloadSize) {}

std::unique_ptr<H264SeiDataParser::SeiDataState> H264SeiDataParser::ParseSeiData(
    const uint8_t *data, size_t length, struct H264BitstreamParserState* bitstream_parser_state) {
  std::vector<uint8_t> unpacked_buffer = UnescapeRbsp(data, length);
  BitBuffer bit_buffer(unpacked_buffer.data(), unpacked_buffer.size());
  return ParseSeiData(&bit_buffer, bitstream_parser_state);
}

std::unique_ptr<H264SeiDataParser::SeiDataState> H264SeiDataParser::ParseSeiData(
    BitBuffer *bit_buffer, struct H264BitstreamParserState* bitstream_parser_state) {
  uint32_t payloadType = ReadSeiTypeOrSize(bit_buffer);
  uint32_t payloadSize = ReadSeiTypeOrSize(bit_buffer);
  size_t byteOffset = 0;
  size_t bitOffset = 0;
  bit_buffer->GetCurrentOffset(&byteOffset, &bitOffset);

  std::unique_ptr<H264SeiDataParser::SeiDataState> result = ParseSeiPayload(bit_buffer, payloadType, payloadSize, bitstream_parser_state);
  bit_buffer->Seek(byteOffset + payloadSize, 0);
  return result;
}

uint32_t H264SeiDataParser::ReadSeiTypeOrSize(
    BitBuffer *bit_buffer) {
  uint32_t val = 0;
  uint8_t byte = 0;

  while (bit_buffer->ReadUInt8(byte) && byte == 0xff) {
    val += 0xff;
  }

  return val + byte;
}

std::unique_ptr<H264SeiDataParser::SeiDataState> H264SeiDataParser::ParseSeiPayload(
    BitBuffer *bit_buffer, uint32_t payloadType, uint32_t payloadSize, struct H264BitstreamParserState* bitstream_parser_state) {
  switch (payloadType)
  {
  case SeiPayloadType::PIC_TIMING: return ParsePicTiming(bit_buffer, payloadType, payloadSize, bitstream_parser_state);
  default: return std::make_unique<SeiDataState>(payloadType, payloadSize);
  }
}

std::unique_ptr<H264SeiDataParser::PicTimingState> H264SeiDataParser::ParsePicTiming(
    BitBuffer *bit_buffer, uint32_t payloadType, uint32_t payloadSize, struct H264BitstreamParserState* bitstream_parser_state)
{
  static constexpr auto sei_num_clock_ts_table = std::to_array({ 1, 1, 1, 2, 2, 3, 3, 2, 3 });

  auto result = std::make_unique<PicTimingState>(payloadType, payloadSize);
  if(bitstream_parser_state->sps.empty()) {
    return nullptr;
  }

  //TODO delay parsing to next SLICE NAL to get correct sps index
  auto sps = bitstream_parser_state->sps.begin()->second;
  if(!sps || !sps->sps_data || !sps->sps_data->vui_parameters) {
    return nullptr;
  }

  auto& vui = sps->sps_data->vui_parameters;
  uint32_t time_offset_length = 0;
  if (vui->nal_hrd_parameters_present_flag || vui->vcl_hrd_parameters_present_flag) {
    auto& hrd = vui->nal_hrd_parameters_present_flag ? vui->nal_hrd_parameters : vui->vcl_hrd_parameters;
    uint64_t readBuf = 0;

    if(!bit_buffer->ReadBits(hrd->cpb_removal_delay_length_minus1 + 1, readBuf)) {
      return nullptr;
    }
    result->cpb_removal_delay = readBuf;

    if(!bit_buffer->ReadBits(hrd->dpb_output_delay_length_minus1 + 1, readBuf)) {
      return nullptr;
    }
    result->dpb_output_delay = readBuf;
    time_offset_length = hrd->time_offset_length;
  }

  if(vui->pic_struct_present_flag) {
    uint64_t readBuf = 0;

    if(!bit_buffer->ReadBits(4, readBuf)) {
      return nullptr;
    }
    result->pic_struct = readBuf;

    if(result->pic_struct >= sei_num_clock_ts_table.size()) {
      return nullptr;
    }
    result->num_clock_ts = sei_num_clock_ts_table[result->pic_struct];

    for (size_t i = 0; i < result->num_clock_ts; ++i) {
      uint64_t readBuf = 0;
      if(!bit_buffer->ReadBits(1, readBuf)) {
        return nullptr;
      }

      if(!readBuf) {
        continue;
      }

      PicTimingState::TimestampData timestamp;
      if(!PicTimingState::TimestampData::parse(timestamp, bit_buffer, time_offset_length)) {
        return nullptr;
      }
      result->timestamps.push_back(timestamp);
    }       
  }

  return result;
}

std::unique_ptr<H264SeiParser::SeiState> H264SeiParser::ParseSei(
    const uint8_t *data, size_t length, struct H264BitstreamParserState* bitstream_parser_state) {
  std::vector<uint8_t> unpacked_buffer = UnescapeRbsp(data, length);
  BitBuffer bit_buffer(unpacked_buffer.data(), unpacked_buffer.size());
  return ParseSei(&bit_buffer, bitstream_parser_state);
}

// 7.3.2.3.1 Supplemental enhancement information message syntax
std::unique_ptr<H264SeiParser::SeiState> H264SeiParser::ParseSei(
    BitBuffer *bit_buffer, struct H264BitstreamParserState* bitstream_parser_state) {
  auto result = std::make_unique<SeiState>();
  do {
    result->sei_data.push_back(H264SeiDataParser::ParseSeiData(bit_buffer, bitstream_parser_state));
  }
  while(more_rbsp_data(bit_buffer));

  rbsp_trailing_bits(bit_buffer);

  return result;
}

bool H264SeiDataParser::PicTimingState::TimestampData::parse(
    TimestampData &timestamp, BitBuffer *bit_buffer, uint32_t time_offset_length) {
  uint64_t readBuf = 0;
  if(!bit_buffer->ReadBits(2, readBuf)) {
    return false;
  }
  timestamp.ct_type = readBuf;

  if(!bit_buffer->ReadBits(1, readBuf)) {
    return false;
  }
  timestamp.nuit_field_based_flag = readBuf;

  if(!bit_buffer->ReadBits(5, readBuf)) {
    return false;
  }
  timestamp.counting_type = readBuf;

  if(!bit_buffer->ReadBits(1, readBuf)) {
    return false;
  }
  bool full_timestamp_flag = readBuf;

  if(!bit_buffer->ReadBits(1, readBuf)) {
    return false;
  }
  timestamp.discontinuity_flag = readBuf;

  if(!bit_buffer->ReadBits(1, readBuf)) {
    return false;
  }
  timestamp.cnt_dropped_flag = readBuf;

  if(!bit_buffer->ReadBits(8, readBuf)) {
    return false;
  }
  timestamp.n_frames = readBuf;

  if(!parseTimestampValues(timestamp, bit_buffer, full_timestamp_flag)) {
    return false;
  }

  if(!time_offset_length) {
    timestamp.time_offset = 0;
    return true;
  }

  if(!bit_buffer->ReadBits(time_offset_length, readBuf)) {
    return false;
  }
  timestamp.time_offset = readBuf;
      
  return true;
}

bool H264SeiDataParser::PicTimingState::TimestampData::parseTimestampValues(
    TimestampData &timestamp, BitBuffer *bit_buffer, bool full_timestamp_flag) {
  uint64_t readBuf = 0;
  if (full_timestamp_flag) {
    if(!bit_buffer->ReadBits(6, readBuf)) {
      return false;
    }
    timestamp.seconds_value = readBuf;

    if(!bit_buffer->ReadBits(6, readBuf)) {
      return false;
    }
    timestamp.minutes_value = readBuf;

    if(!bit_buffer->ReadBits(5, readBuf)) {
      return false;
    }
    timestamp.hours_value = readBuf;
  } 
  else {
    if(!bit_buffer->ReadBits(1, readBuf)) {
      return false;
    }

    if(!readBuf) {
      timestamp.seconds_value = timestamp.minutes_value = timestamp.hours_value = 0;
      return true;
    }

    if(!bit_buffer->ReadBits(6, readBuf)) {
      return false;
    }
    timestamp.seconds_value = readBuf;

    if(!bit_buffer->ReadBits(1, readBuf)) {
      return false;
    }

    if(!readBuf) {
      timestamp.minutes_value = timestamp.hours_value = 0;
      return true;
    }

    if(!bit_buffer->ReadBits(6, readBuf)) {
      return false;
    }
    timestamp.minutes_value = readBuf;

    if(!bit_buffer->ReadBits(1, readBuf)) {
      return false;
    }

    if(!readBuf) {
      timestamp.hours_value = 0;
      return true;
    }

    if(!bit_buffer->ReadBits(5, readBuf)) {
      return false;
    }
    timestamp.hours_value = readBuf;
  }
  return true;
}

} // namespace h264nal
#pragma once

#include <stdio.h>

#include <memory>
#include <vector>

#include "h264_common.h"
#include "h264_vui_parameters_parser.h"
#include "rtc_common.h"

namespace h264nal {

enum SeiPayloadType : uint8_t {
    BUFFERING_PERIOD                           = 0,
    PIC_TIMING                                 = 1,
    PAN_SCAN_RECT                              = 2,
    FILLER_PAYLOAD                             = 3,
    USER_DATA_REGISTERED_ITU_T_T35             = 4,
    USER_DATA_UNREGISTERED                     = 5,
    RECOVERY_POINT                             = 6,
    DEC_REF_PIC_MARKING_REPETITION             = 7,
    SPARE_PIC                                  = 8,
    SCENE_INFO                                 = 9,
    SUB_SEQ_INFO                               = 10,
    SUB_SEQ_LAYER_CHARACTERISTICS              = 11,
    SUB_SEQ_CHARACTERISTICS                    = 12,
    FULL_FRAME_FREEZE                          = 13,
    FULL_FRAME_FREEZE_RELEASE                  = 14,
    FULL_FRAME_SNAPSHOT                        = 15,
    PROGRESSIVE_REFINEMENT_SEGMENT_START       = 16,
    PROGRESSIVE_REFINEMENT_SEGMENT_END         = 17,
    MOTION_CONSTRAINED_SLICE_GROUP_SET         = 18,
    FILM_GRAIN_CHARACTERISTICS                 = 19,
    DEBLOCKING_FILTER_DISPLAY_PREFERENCE       = 20,
    STEREO_VIDEO_INFO                          = 21,
    POST_FILTER_HINT                           = 22,
    TONE_MAPPING_INFO                          = 23,
    SCALABILITY_INFO                           = 24,  // Annex G
    SUB_PIC_SCALABLE_LAYER                     = 25,  // Annex G
    NON_REQUIRED_LAYER_REP                     = 26,  // Annex G
    PRIORITY_LAYER_INFO                        = 27,  // Annex G
    LAYERS_NOT_PRESENT                         = 28,  // Annex G
    LAYER_DEPENDENCY_CHANGE                    = 29,  // Annex G
    SCALABLE_NESTING                           = 30,  // Annex G
    BASE_LAYER_TEMPORAL_HRD                    = 31,  // Annex G
    QUALITY_LAYER_INTEGRITY_CHECK              = 32,  // Annex G
    REDUNDANT_PIC_PROPERTY                     = 33,  // Annex G
    TL0_DEP_REP_INDEX                          = 34,  // Annex G
    TL_SWITCHING_POINT                         = 35,  // Annex G
    PARALLEL_DECODING_INFO                     = 36,  // Annex H
    MVC_SCALABLE_NESTING                       = 37,  // Annex H
    VIEW_SCALABILITY_INFO                      = 38,  // Annex H
    MULTIVIEW_SCENE_INFO                       = 39,  // Annex H
    MULTIVIEW_ACQUISITION_INFO                 = 40,  // Annex H
    NON_REQUIRED_VIEW_COMPONENT                = 41,  // Annex H
    VIEW_DEPENDENCY_CHANGE                     = 42,  // Annex H
    OPERATION_POINTS_NOT_PRESENT               = 43,  // Annex H
    BASE_VIEW_TEMPORAL_HRD                     = 44,  // Annex H
    FRAME_PACKING_ARRANGEMENT                  = 45,
    MULTIVIEW_VIEW_POSITION                    = 46,  // Annex H
    DISPLAY_ORIENTATION                        = 47,
    MVCD_SCALABLE_NESTING                      = 48,  // Annex I
    MVCD_VIEW_SCALABILITY_INFO                 = 49,  // Annex I
    DEPTH_REPRESENTATION_INFO                  = 50,  // Annex I
    THREE_DIMENSIONAL_REFERENCE_DISPLAYS_INFO  = 51,  // Annex I
    DEPTH_TIMING                               = 52,  // Annex I
    DEPTH_SAMPLING_INFO                        = 53,  // Annex I
    CONSTRAINED_DEPTH_PARAMETER_SET_IDENTIFIER = 54,  // Annex J
    GREEN_METADATA                             = 56,  // ISO/IEC 23001-11
    MASTERING_DISPLAY_COLOUR_VOLUME            = 137,
    COLOUR_REMAPPING_INFO                      = 142,
    CONTENT_LIGHT_LEVEL_INFO                   = 144,
    ALTERNATIVE_TRANSFER_CHARACTERISTICS       = 147,
    AMBIENT_VIEWING_ENVIRONMENT                = 148,
    CONTENT_COLOUR_VOLUME                      = 149,
    EQUIRECTANGULAR_PROJECTION                 = 150,
    CUBEMAP_PROJECTION                         = 151,
    SPHERE_ROTATION                            = 154,
    REGIONWISE_PACKING                         = 155,
    OMNI_VIEWPORT                              = 156,
    ALTERNATIVE_DEPTH_INFO                     = 181,  // Annex I
    SEI_MANIFEST                               = 200,
    SEI_PREFIX_INDICATION                      = 201,
};


class H264SeiDataParser {
public:
    struct SeiDataState {
        SeiDataState(uint32_t _payloadType, uint32_t _payloadSize);
        virtual ~SeiDataState() = default;

        uint32_t payloadType;
        uint32_t payloadSize;
    };

    struct PicTimingState : SeiDataState {
        using SeiDataState::SeiDataState;

        uint8_t cpb_removal_delay = 0;
        uint8_t dpb_output_delay = 0;
        uint8_t pic_struct = 0;
        uint8_t num_clock_ts = 0;

        struct TimestampData {
            uint8_t ct_type;
            bool nuit_field_based_flag;
            uint8_t counting_type;
            bool discontinuity_flag;
            bool cnt_dropped_flag;
            uint8_t n_frames;
            uint8_t seconds_value;
            uint8_t minutes_value;
            uint8_t hours_value;
            uint32_t time_offset;

            static bool parse(TimestampData& data, BitBuffer* bit_buffer, uint32_t time_offset_length);
            static bool parseTimestampValues(TimestampData& data, BitBuffer* bit_buffer, bool full_timestamp_flag);
        };

        std::vector<TimestampData> timestamps;
    };

    // Unpack RBSP and parse SEI state from the supplied buffer.
    static std::unique_ptr<SeiDataState> ParseSeiData(const uint8_t* data,
                                            size_t length,
                                            struct H264BitstreamParserState* bitstream_parser_state);

    static std::unique_ptr<SeiDataState> ParseSeiData(BitBuffer* bit_buffer,
                                            struct H264BitstreamParserState* bitstream_parser_state);

    static uint32_t ReadSeiTypeOrSize(BitBuffer* bit_buffer);

    static std::unique_ptr<SeiDataState> ParseSeiPayload(BitBuffer* bit_buffer, 
                                            uint32_t payloadType, 
                                            uint32_t payloadSize,
                                            struct H264BitstreamParserState* bitstream_parser_state);
    static std::unique_ptr<PicTimingState> ParsePicTiming(BitBuffer* bit_buffer, 
                                            uint32_t payloadType, 
                                            uint32_t payloadSize,
                                            struct H264BitstreamParserState* bitstream_parser_state);
};

class H264SeiParser {
public:
    struct SeiState {
        SeiState() = default;
        ~SeiState() = default;
        // disable copy ctor, move ctor, and copy&move assignments
        SeiState(const SeiState&) = delete;
        SeiState(SeiState&&) = delete;
        SeiState& operator=(const SeiState&) = delete;
        SeiState& operator=(SeiState&&) = delete;

#ifdef FDUMP_DEFINE
        void fdump(FILE* outfp, int indent_level,
                ParsingOptions parsing_options) const;
#endif  // FDUMP_DEFINE

        std::vector<std::unique_ptr<struct H264SeiDataParser::SeiDataState>> sei_data;
    };

    // Unpack RBSP and parse SEI state from the supplied buffer.
    static std::unique_ptr<SeiState> ParseSei(const uint8_t* data,
                                            size_t length, 
                                            struct H264BitstreamParserState* bitstream_parser_state);

    static std::unique_ptr<SeiState> ParseSei(BitBuffer* bit_buffer,
                                            struct H264BitstreamParserState* bitstream_parser_state);
};

} // namespace h264nal
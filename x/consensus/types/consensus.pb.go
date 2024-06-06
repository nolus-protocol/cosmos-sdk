// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cosmos/consensus/v1/consensus.proto

package types

import (
	fmt "fmt"
	v1 "github.com/cometbft/cometbft/api/cometbft/types/v1"
	proto "github.com/cosmos/gogoproto/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// ConsensusMsgParams is the Msg/Params request type. This is a consensus message that is sent from cometbft.
type ConsensusMsgParams struct {
	// params defines the x/consensus parameters to be passed from comet.
	//
	// NOTE: All parameters must be supplied.
	Version   *v1.VersionParams   `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Block     *v1.BlockParams     `protobuf:"bytes,2,opt,name=block,proto3" json:"block,omitempty"`
	Evidence  *v1.EvidenceParams  `protobuf:"bytes,3,opt,name=evidence,proto3" json:"evidence,omitempty"`
	Validator *v1.ValidatorParams `protobuf:"bytes,4,opt,name=validator,proto3" json:"validator,omitempty"`
	Abci      *v1.ABCIParams      `protobuf:"bytes,5,opt,name=abci,proto3" json:"abci,omitempty"` // Deprecated: Do not use.
	Synchrony *v1.SynchronyParams `protobuf:"bytes,6,opt,name=synchrony,proto3" json:"synchrony,omitempty"`
	Feature   *v1.FeatureParams   `protobuf:"bytes,7,opt,name=feature,proto3" json:"feature,omitempty"`
}

func (m *ConsensusMsgParams) Reset()         { *m = ConsensusMsgParams{} }
func (m *ConsensusMsgParams) String() string { return proto.CompactTextString(m) }
func (*ConsensusMsgParams) ProtoMessage()    {}
func (*ConsensusMsgParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_7ed86dd7d42fb61b, []int{0}
}
func (m *ConsensusMsgParams) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ConsensusMsgParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ConsensusMsgParams.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ConsensusMsgParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConsensusMsgParams.Merge(m, src)
}
func (m *ConsensusMsgParams) XXX_Size() int {
	return m.Size()
}
func (m *ConsensusMsgParams) XXX_DiscardUnknown() {
	xxx_messageInfo_ConsensusMsgParams.DiscardUnknown(m)
}

var xxx_messageInfo_ConsensusMsgParams proto.InternalMessageInfo

func (m *ConsensusMsgParams) GetVersion() *v1.VersionParams {
	if m != nil {
		return m.Version
	}
	return nil
}

func (m *ConsensusMsgParams) GetBlock() *v1.BlockParams {
	if m != nil {
		return m.Block
	}
	return nil
}

func (m *ConsensusMsgParams) GetEvidence() *v1.EvidenceParams {
	if m != nil {
		return m.Evidence
	}
	return nil
}

func (m *ConsensusMsgParams) GetValidator() *v1.ValidatorParams {
	if m != nil {
		return m.Validator
	}
	return nil
}

// Deprecated: Do not use.
func (m *ConsensusMsgParams) GetAbci() *v1.ABCIParams {
	if m != nil {
		return m.Abci
	}
	return nil
}

func (m *ConsensusMsgParams) GetSynchrony() *v1.SynchronyParams {
	if m != nil {
		return m.Synchrony
	}
	return nil
}

func (m *ConsensusMsgParams) GetFeature() *v1.FeatureParams {
	if m != nil {
		return m.Feature
	}
	return nil
}

// ConsensusMsgParamsResponse defines the response structure for executing a
// ConsensusMsgParams message.
type ConsensusMsgParamsResponse struct {
}

func (m *ConsensusMsgParamsResponse) Reset()         { *m = ConsensusMsgParamsResponse{} }
func (m *ConsensusMsgParamsResponse) String() string { return proto.CompactTextString(m) }
func (*ConsensusMsgParamsResponse) ProtoMessage()    {}
func (*ConsensusMsgParamsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_7ed86dd7d42fb61b, []int{1}
}
func (m *ConsensusMsgParamsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ConsensusMsgParamsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ConsensusMsgParamsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ConsensusMsgParamsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConsensusMsgParamsResponse.Merge(m, src)
}
func (m *ConsensusMsgParamsResponse) XXX_Size() int {
	return m.Size()
}
func (m *ConsensusMsgParamsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ConsensusMsgParamsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ConsensusMsgParamsResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ConsensusMsgParams)(nil), "cosmos.consensus.v1.ConsensusMsgParams")
	proto.RegisterType((*ConsensusMsgParamsResponse)(nil), "cosmos.consensus.v1.ConsensusMsgParamsResponse")
}

func init() {
	proto.RegisterFile("cosmos/consensus/v1/consensus.proto", fileDescriptor_7ed86dd7d42fb61b)
}

var fileDescriptor_7ed86dd7d42fb61b = []byte{
	// 349 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0xd2, 0xcb, 0x4e, 0x02, 0x31,
	0x14, 0x06, 0x60, 0x86, 0xab, 0xd6, 0x5d, 0xdd, 0x34, 0x44, 0x1b, 0xc4, 0x8d, 0x1b, 0x3b, 0xc1,
	0xcb, 0xc6, 0xc4, 0x44, 0x87, 0x68, 0x74, 0x61, 0x62, 0x30, 0x71, 0xe1, 0x6e, 0xa6, 0x14, 0x98,
	0x00, 0xd3, 0xc9, 0xb4, 0x4c, 0xe4, 0x2d, 0x7c, 0x20, 0x1f, 0xc0, 0x25, 0x4b, 0x97, 0x06, 0x5e,
	0xc4, 0xf4, 0x06, 0x26, 0x0e, 0x2b, 0x42, 0xfb, 0x7f, 0xe7, 0x34, 0x67, 0x0e, 0x38, 0xa6, 0x5c,
	0x4c, 0xb9, 0xf0, 0x29, 0x4f, 0x04, 0x4b, 0xc4, 0x4c, 0xf8, 0x79, 0x67, 0xf3, 0x87, 0xa4, 0x19,
	0x97, 0x1c, 0xee, 0x9b, 0x10, 0xd9, 0x9c, 0xe7, 0x9d, 0x26, 0xa6, 0x7c, 0xca, 0x64, 0x34, 0x90,
	0xbe, 0x9c, 0xa7, 0x4c, 0xbb, 0x34, 0xcc, 0xc2, 0xa9, 0x45, 0xed, 0xcf, 0x0a, 0x80, 0x5d, 0x07,
	0x9e, 0xc4, 0xf0, 0x59, 0x5f, 0xc2, 0x2b, 0xd0, 0xc8, 0x59, 0x26, 0x62, 0x9e, 0x20, 0xaf, 0xe5,
	0x9d, 0xec, 0x9d, 0xb5, 0x88, 0x2b, 0x44, 0x74, 0x21, 0x92, 0x77, 0xc8, 0xab, 0x49, 0x18, 0xd2,
	0x73, 0x00, 0x5e, 0x80, 0x5a, 0x34, 0xe1, 0x74, 0x8c, 0xca, 0x5a, 0xe2, 0x02, 0x19, 0xa8, 0x7b,
	0xeb, 0x4c, 0x18, 0x5e, 0x83, 0x1d, 0x96, 0xc7, 0x7d, 0x96, 0x50, 0x86, 0x2a, 0x1a, 0x1e, 0x15,
	0xc0, 0x3b, 0x1b, 0xb1, 0x76, 0x4d, 0xe0, 0x0d, 0xd8, 0xcd, 0xc3, 0x49, 0xdc, 0x0f, 0x25, 0xcf,
	0x50, 0x55, 0xfb, 0x76, 0xd1, 0x93, 0x5d, 0xc6, 0x16, 0xd8, 0x20, 0x78, 0x09, 0xaa, 0x61, 0x44,
	0x63, 0x54, 0xd3, 0xf8, 0xb0, 0x00, 0xdf, 0x06, 0xdd, 0x47, 0xe3, 0x82, 0x32, 0xf2, 0x7a, 0x3a,
	0xae, 0x1a, 0x8b, 0x79, 0x42, 0x47, 0x19, 0x4f, 0xe6, 0xa8, 0xbe, 0xb5, 0xf1, 0x8b, 0xcb, 0xb8,
	0xc6, 0x6b, 0xa4, 0x66, 0x3d, 0x60, 0xa1, 0x9c, 0x65, 0x0c, 0x35, 0xb6, 0xce, 0xfa, 0xde, 0x24,
	0xdc, 0xac, 0x2d, 0x68, 0x1f, 0x80, 0xe6, 0xff, 0xaf, 0xd7, 0x63, 0x22, 0x55, 0x87, 0xc1, 0xc3,
	0xd7, 0x12, 0x7b, 0x8b, 0x25, 0xf6, 0x7e, 0x96, 0xd8, 0xfb, 0x58, 0xe1, 0xd2, 0x62, 0x85, 0x4b,
	0xdf, 0x2b, 0x5c, 0x7a, 0x23, 0xc3, 0x58, 0x8e, 0x66, 0x91, 0x6a, 0xe4, 0xaf, 0x77, 0x4b, 0xfd,
	0x9c, 0x8a, 0xfe, 0xd8, 0x7f, 0xff, 0xb3, 0x68, 0xfa, 0x05, 0x51, 0x5d, 0x6f, 0xcb, 0xf9, 0x6f,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x79, 0x8b, 0x65, 0x41, 0x89, 0x02, 0x00, 0x00,
}

func (m *ConsensusMsgParams) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ConsensusMsgParams) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ConsensusMsgParams) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Feature != nil {
		{
			size, err := m.Feature.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintConsensus(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x3a
	}
	if m.Synchrony != nil {
		{
			size, err := m.Synchrony.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintConsensus(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x32
	}
	if m.Abci != nil {
		{
			size, err := m.Abci.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintConsensus(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x2a
	}
	if m.Validator != nil {
		{
			size, err := m.Validator.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintConsensus(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if m.Evidence != nil {
		{
			size, err := m.Evidence.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintConsensus(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.Block != nil {
		{
			size, err := m.Block.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintConsensus(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Version != nil {
		{
			size, err := m.Version.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintConsensus(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ConsensusMsgParamsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ConsensusMsgParamsResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ConsensusMsgParamsResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func encodeVarintConsensus(dAtA []byte, offset int, v uint64) int {
	offset -= sovConsensus(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ConsensusMsgParams) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Version != nil {
		l = m.Version.Size()
		n += 1 + l + sovConsensus(uint64(l))
	}
	if m.Block != nil {
		l = m.Block.Size()
		n += 1 + l + sovConsensus(uint64(l))
	}
	if m.Evidence != nil {
		l = m.Evidence.Size()
		n += 1 + l + sovConsensus(uint64(l))
	}
	if m.Validator != nil {
		l = m.Validator.Size()
		n += 1 + l + sovConsensus(uint64(l))
	}
	if m.Abci != nil {
		l = m.Abci.Size()
		n += 1 + l + sovConsensus(uint64(l))
	}
	if m.Synchrony != nil {
		l = m.Synchrony.Size()
		n += 1 + l + sovConsensus(uint64(l))
	}
	if m.Feature != nil {
		l = m.Feature.Size()
		n += 1 + l + sovConsensus(uint64(l))
	}
	return n
}

func (m *ConsensusMsgParamsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func sovConsensus(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozConsensus(x uint64) (n int) {
	return sovConsensus(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ConsensusMsgParams) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConsensus
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ConsensusMsgParams: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ConsensusMsgParams: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConsensus
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConsensus
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Version == nil {
				m.Version = &v1.VersionParams{}
			}
			if err := m.Version.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Block", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConsensus
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConsensus
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Block == nil {
				m.Block = &v1.BlockParams{}
			}
			if err := m.Block.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Evidence", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConsensus
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConsensus
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Evidence == nil {
				m.Evidence = &v1.EvidenceParams{}
			}
			if err := m.Evidence.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Validator", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConsensus
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConsensus
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Validator == nil {
				m.Validator = &v1.ValidatorParams{}
			}
			if err := m.Validator.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Abci", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConsensus
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConsensus
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Abci == nil {
				m.Abci = &v1.ABCIParams{}
			}
			if err := m.Abci.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Synchrony", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConsensus
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConsensus
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Synchrony == nil {
				m.Synchrony = &v1.SynchronyParams{}
			}
			if err := m.Synchrony.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Feature", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConsensus
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConsensus
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Feature == nil {
				m.Feature = &v1.FeatureParams{}
			}
			if err := m.Feature.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConsensus(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthConsensus
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ConsensusMsgParamsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConsensus
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ConsensusMsgParamsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ConsensusMsgParamsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipConsensus(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthConsensus
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipConsensus(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowConsensus
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConsensus
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthConsensus
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupConsensus
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthConsensus
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthConsensus        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConsensus          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupConsensus = fmt.Errorf("proto: unexpected end of group")
)
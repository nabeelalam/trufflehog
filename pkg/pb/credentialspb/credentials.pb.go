// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v4.25.2
// source: credentials.proto

package credentialspb

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Unauthenticated struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Unauthenticated) Reset() {
	*x = Unauthenticated{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Unauthenticated) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Unauthenticated) ProtoMessage() {}

func (x *Unauthenticated) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Unauthenticated.ProtoReflect.Descriptor instead.
func (*Unauthenticated) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{0}
}

type SSHAuth struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SSHAuth) Reset() {
	*x = SSHAuth{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SSHAuth) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SSHAuth) ProtoMessage() {}

func (x *SSHAuth) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SSHAuth.ProtoReflect.Descriptor instead.
func (*SSHAuth) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{1}
}

type CloudEnvironment struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CloudEnvironment) Reset() {
	*x = CloudEnvironment{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CloudEnvironment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CloudEnvironment) ProtoMessage() {}

func (x *CloudEnvironment) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CloudEnvironment.ProtoReflect.Descriptor instead.
func (*CloudEnvironment) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{2}
}

type BasicAuth struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Username string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *BasicAuth) Reset() {
	*x = BasicAuth{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BasicAuth) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BasicAuth) ProtoMessage() {}

func (x *BasicAuth) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BasicAuth.ProtoReflect.Descriptor instead.
func (*BasicAuth) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{3}
}

func (x *BasicAuth) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *BasicAuth) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type Header struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *Header) Reset() {
	*x = Header{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Header) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Header) ProtoMessage() {}

func (x *Header) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Header.ProtoReflect.Descriptor instead.
func (*Header) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{4}
}

func (x *Header) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Header) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

type ClientCredentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TenantId     string `protobuf:"bytes,1,opt,name=tenant_id,json=tenantId,proto3" json:"tenant_id,omitempty"`
	ClientId     string `protobuf:"bytes,2,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	ClientSecret string `protobuf:"bytes,3,opt,name=client_secret,json=clientSecret,proto3" json:"client_secret,omitempty"`
}

func (x *ClientCredentials) Reset() {
	*x = ClientCredentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientCredentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientCredentials) ProtoMessage() {}

func (x *ClientCredentials) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientCredentials.ProtoReflect.Descriptor instead.
func (*ClientCredentials) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{5}
}

func (x *ClientCredentials) GetTenantId() string {
	if x != nil {
		return x.TenantId
	}
	return ""
}

func (x *ClientCredentials) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *ClientCredentials) GetClientSecret() string {
	if x != nil {
		return x.ClientSecret
	}
	return ""
}

type ClientCertificate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TenantId            string `protobuf:"bytes,1,opt,name=tenant_id,json=tenantId,proto3" json:"tenant_id,omitempty"`
	ClientId            string `protobuf:"bytes,2,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	CertificatePath     string `protobuf:"bytes,3,opt,name=certificate_path,json=certificatePath,proto3" json:"certificate_path,omitempty"`
	CertificatePassword string `protobuf:"bytes,4,opt,name=certificate_password,json=certificatePassword,proto3" json:"certificate_password,omitempty"`
}

func (x *ClientCertificate) Reset() {
	*x = ClientCertificate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientCertificate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientCertificate) ProtoMessage() {}

func (x *ClientCertificate) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientCertificate.ProtoReflect.Descriptor instead.
func (*ClientCertificate) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{6}
}

func (x *ClientCertificate) GetTenantId() string {
	if x != nil {
		return x.TenantId
	}
	return ""
}

func (x *ClientCertificate) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *ClientCertificate) GetCertificatePath() string {
	if x != nil {
		return x.CertificatePath
	}
	return ""
}

func (x *ClientCertificate) GetCertificatePassword() string {
	if x != nil {
		return x.CertificatePassword
	}
	return ""
}

type Oauth2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RefreshToken string `protobuf:"bytes,1,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	ClientId     string `protobuf:"bytes,2,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	ClientSecret string `protobuf:"bytes,3,opt,name=client_secret,json=clientSecret,proto3" json:"client_secret,omitempty"`
	AccessToken  string `protobuf:"bytes,4,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
}

func (x *Oauth2) Reset() {
	*x = Oauth2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Oauth2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Oauth2) ProtoMessage() {}

func (x *Oauth2) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Oauth2.ProtoReflect.Descriptor instead.
func (*Oauth2) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{7}
}

func (x *Oauth2) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

func (x *Oauth2) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *Oauth2) GetClientSecret() string {
	if x != nil {
		return x.ClientSecret
	}
	return ""
}

func (x *Oauth2) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

type KeySecret struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key    string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Secret string `protobuf:"bytes,2,opt,name=secret,proto3" json:"secret,omitempty"`
}

func (x *KeySecret) Reset() {
	*x = KeySecret{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeySecret) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeySecret) ProtoMessage() {}

func (x *KeySecret) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeySecret.ProtoReflect.Descriptor instead.
func (*KeySecret) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{8}
}

func (x *KeySecret) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *KeySecret) GetSecret() string {
	if x != nil {
		return x.Secret
	}
	return ""
}

type AWSSessionTokenSecret struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key          string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Secret       string `protobuf:"bytes,2,opt,name=secret,proto3" json:"secret,omitempty"`
	SessionToken string `protobuf:"bytes,3,opt,name=session_token,json=sessionToken,proto3" json:"session_token,omitempty"`
}

func (x *AWSSessionTokenSecret) Reset() {
	*x = AWSSessionTokenSecret{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AWSSessionTokenSecret) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AWSSessionTokenSecret) ProtoMessage() {}

func (x *AWSSessionTokenSecret) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AWSSessionTokenSecret.ProtoReflect.Descriptor instead.
func (*AWSSessionTokenSecret) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{9}
}

func (x *AWSSessionTokenSecret) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *AWSSessionTokenSecret) GetSecret() string {
	if x != nil {
		return x.Secret
	}
	return ""
}

func (x *AWSSessionTokenSecret) GetSessionToken() string {
	if x != nil {
		return x.SessionToken
	}
	return ""
}

type AWS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key    string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Secret string `protobuf:"bytes,2,opt,name=secret,proto3" json:"secret,omitempty"`
	Region string `protobuf:"bytes,3,opt,name=region,proto3" json:"region,omitempty"`
}

func (x *AWS) Reset() {
	*x = AWS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AWS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AWS) ProtoMessage() {}

func (x *AWS) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AWS.ProtoReflect.Descriptor instead.
func (*AWS) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{10}
}

func (x *AWS) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *AWS) GetSecret() string {
	if x != nil {
		return x.Secret
	}
	return ""
}

func (x *AWS) GetRegion() string {
	if x != nil {
		return x.Region
	}
	return ""
}

type SES struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Creds      *AWS     `protobuf:"bytes,1,opt,name=creds,proto3" json:"creds,omitempty"`
	Sender     string   `protobuf:"bytes,2,opt,name=sender,proto3" json:"sender,omitempty"`
	Recipients []string `protobuf:"bytes,3,rep,name=recipients,proto3" json:"recipients,omitempty"`
}

func (x *SES) Reset() {
	*x = SES{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SES) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SES) ProtoMessage() {}

func (x *SES) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SES.ProtoReflect.Descriptor instead.
func (*SES) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{11}
}

func (x *SES) GetCreds() *AWS {
	if x != nil {
		return x.Creds
	}
	return nil
}

func (x *SES) GetSender() string {
	if x != nil {
		return x.Sender
	}
	return ""
}

func (x *SES) GetRecipients() []string {
	if x != nil {
		return x.Recipients
	}
	return nil
}

type GitHubApp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PrivateKey     string `protobuf:"bytes,1,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	InstallationId string `protobuf:"bytes,2,opt,name=installation_id,json=installationId,proto3" json:"installation_id,omitempty"`
	AppId          string `protobuf:"bytes,3,opt,name=app_id,json=appId,proto3" json:"app_id,omitempty"`
}

func (x *GitHubApp) Reset() {
	*x = GitHubApp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GitHubApp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GitHubApp) ProtoMessage() {}

func (x *GitHubApp) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GitHubApp.ProtoReflect.Descriptor instead.
func (*GitHubApp) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{12}
}

func (x *GitHubApp) GetPrivateKey() string {
	if x != nil {
		return x.PrivateKey
	}
	return ""
}

func (x *GitHubApp) GetInstallationId() string {
	if x != nil {
		return x.InstallationId
	}
	return ""
}

func (x *GitHubApp) GetAppId() string {
	if x != nil {
		return x.AppId
	}
	return ""
}

type SlackTokens struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AppToken    string `protobuf:"bytes,1,opt,name=app_token,json=appToken,proto3" json:"app_token,omitempty"`
	BotToken    string `protobuf:"bytes,2,opt,name=bot_token,json=botToken,proto3" json:"bot_token,omitempty"`
	ClientToken string `protobuf:"bytes,3,opt,name=client_token,json=clientToken,proto3" json:"client_token,omitempty"`
}

func (x *SlackTokens) Reset() {
	*x = SlackTokens{}
	if protoimpl.UnsafeEnabled {
		mi := &file_credentials_proto_msgTypes[13]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SlackTokens) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SlackTokens) ProtoMessage() {}

func (x *SlackTokens) ProtoReflect() protoreflect.Message {
	mi := &file_credentials_proto_msgTypes[13]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SlackTokens.ProtoReflect.Descriptor instead.
func (*SlackTokens) Descriptor() ([]byte, []int) {
	return file_credentials_proto_rawDescGZIP(), []int{13}
}

func (x *SlackTokens) GetAppToken() string {
	if x != nil {
		return x.AppToken
	}
	return ""
}

func (x *SlackTokens) GetBotToken() string {
	if x != nil {
		return x.BotToken
	}
	return ""
}

func (x *SlackTokens) GetClientToken() string {
	if x != nil {
		return x.ClientToken
	}
	return ""
}

var File_credentials_proto protoreflect.FileDescriptor

var file_credentials_proto_rawDesc = []byte{
	0x0a, 0x11, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73,
	0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x11, 0x0a, 0x0f, 0x55, 0x6e, 0x61,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x22, 0x09, 0x0a, 0x07,
	0x53, 0x53, 0x48, 0x41, 0x75, 0x74, 0x68, 0x22, 0x12, 0x0a, 0x10, 0x43, 0x6c, 0x6f, 0x75, 0x64,
	0x45, 0x6e, 0x76, 0x69, 0x72, 0x6f, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x43, 0x0a, 0x09, 0x42,
	0x61, 0x73, 0x69, 0x63, 0x41, 0x75, 0x74, 0x68, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
	0x22, 0x30, 0x0a, 0x06, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x22, 0x72, 0x0a, 0x11, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x74, 0x65, 0x6e, 0x61, 0x6e,
	0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x65, 0x6e, 0x61,
	0x6e, 0x74, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49,
	0x64, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63, 0x72,
	0x65, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x22, 0xab, 0x01, 0x0a, 0x11, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x1b, 0x0a, 0x09,
	0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x29, 0x0a, 0x10, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x50, 0x61, 0x74,
	0x68, 0x12, 0x31, 0x0a, 0x14, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x13, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x50, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x22, 0x92, 0x01, 0x0a, 0x06, 0x4f, 0x61, 0x75, 0x74, 0x68, 0x32, 0x12,
	0x23, 0x0a, 0x0d, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49,
	0x64, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63, 0x72,
	0x65, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x35, 0x0a, 0x09, 0x4b, 0x65, 0x79,
	0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x63, 0x72,
	0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x22, 0x81, 0x01, 0x0a, 0x15, 0x41, 0x57, 0x53, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x19, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x1f, 0x0a, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x06,
	0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x2c, 0x0a, 0x0d, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa,
	0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x0c, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x59, 0x0a, 0x03, 0x41, 0x57, 0x53, 0x12, 0x19, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10,
	0x01, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x1f, 0x0a, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52,
	0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x67, 0x69, 0x6f,
	0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x22,
	0x65, 0x0a, 0x03, 0x53, 0x45, 0x53, 0x12, 0x26, 0x0a, 0x05, 0x63, 0x72, 0x65, 0x64, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x61, 0x6c, 0x73, 0x2e, 0x41, 0x57, 0x53, 0x52, 0x05, 0x63, 0x72, 0x65, 0x64, 0x73, 0x12, 0x16,
	0x0a, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x12, 0x1e, 0x0a, 0x0a, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69,
	0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x72, 0x65, 0x63, 0x69,
	0x70, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x6c, 0x0a, 0x09, 0x47, 0x69, 0x74, 0x48, 0x75, 0x62,
	0x41, 0x70, 0x70, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,
	0x65, 0x4b, 0x65, 0x79, 0x12, 0x27, 0x0a, 0x0f, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x69,
	0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x15, 0x0a,
	0x06, 0x61, 0x70, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x61,
	0x70, 0x70, 0x49, 0x64, 0x22, 0x6a, 0x0a, 0x0b, 0x53, 0x6c, 0x61, 0x63, 0x6b, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x61, 0x70, 0x70, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x61, 0x70, 0x70, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x12, 0x1b, 0x0a, 0x09, 0x62, 0x6f, 0x74, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x62, 0x6f, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x21, 0x0a,
	0x0c, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x42, 0x3f, 0x5a, 0x3d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74,
	0x72, 0x75, 0x66, 0x66, 0x6c, 0x65, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x74,
	0x72, 0x75, 0x66, 0x66, 0x6c, 0x65, 0x68, 0x6f, 0x67, 0x2f, 0x76, 0x33, 0x2f, 0x70, 0x6b, 0x67,
	0x2f, 0x70, 0x62, 0x2f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x70,
	0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_credentials_proto_rawDescOnce sync.Once
	file_credentials_proto_rawDescData = file_credentials_proto_rawDesc
)

func file_credentials_proto_rawDescGZIP() []byte {
	file_credentials_proto_rawDescOnce.Do(func() {
		file_credentials_proto_rawDescData = protoimpl.X.CompressGZIP(file_credentials_proto_rawDescData)
	})
	return file_credentials_proto_rawDescData
}

var file_credentials_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_credentials_proto_goTypes = []interface{}{
	(*Unauthenticated)(nil),       // 0: credentials.Unauthenticated
	(*SSHAuth)(nil),               // 1: credentials.SSHAuth
	(*CloudEnvironment)(nil),      // 2: credentials.CloudEnvironment
	(*BasicAuth)(nil),             // 3: credentials.BasicAuth
	(*Header)(nil),                // 4: credentials.Header
	(*ClientCredentials)(nil),     // 5: credentials.ClientCredentials
	(*ClientCertificate)(nil),     // 6: credentials.ClientCertificate
	(*Oauth2)(nil),                // 7: credentials.Oauth2
	(*KeySecret)(nil),             // 8: credentials.KeySecret
	(*AWSSessionTokenSecret)(nil), // 9: credentials.AWSSessionTokenSecret
	(*AWS)(nil),                   // 10: credentials.AWS
	(*SES)(nil),                   // 11: credentials.SES
	(*GitHubApp)(nil),             // 12: credentials.GitHubApp
	(*SlackTokens)(nil),           // 13: credentials.SlackTokens
}
var file_credentials_proto_depIdxs = []int32{
	10, // 0: credentials.SES.creds:type_name -> credentials.AWS
	1,  // [1:1] is the sub-list for method output_type
	1,  // [1:1] is the sub-list for method input_type
	1,  // [1:1] is the sub-list for extension type_name
	1,  // [1:1] is the sub-list for extension extendee
	0,  // [0:1] is the sub-list for field type_name
}

func init() { file_credentials_proto_init() }
func file_credentials_proto_init() {
	if File_credentials_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_credentials_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Unauthenticated); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SSHAuth); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CloudEnvironment); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BasicAuth); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Header); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientCredentials); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientCertificate); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Oauth2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeySecret); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AWSSessionTokenSecret); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AWS); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SES); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GitHubApp); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_credentials_proto_msgTypes[13].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SlackTokens); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_credentials_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_credentials_proto_goTypes,
		DependencyIndexes: file_credentials_proto_depIdxs,
		MessageInfos:      file_credentials_proto_msgTypes,
	}.Build()
	File_credentials_proto = out.File
	file_credentials_proto_rawDesc = nil
	file_credentials_proto_goTypes = nil
	file_credentials_proto_depIdxs = nil
}

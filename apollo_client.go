package agollo

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

var (
	defaultClientTimeout = 90 * time.Second
)

const (
	// ENV_APOLLO_ACCESS_KEY 默认从环境变量中读取Apollo的AccessKey
	// 会被显示传入的AccessKey所覆盖
	ENV_APOLLO_ACCESS_KEY = "APOLLO_ACCESS_KEY"

	// ENV_APOLLO_SECRET_KEY 默认从环境变量中读取Apollo的SecretKey，必须是base64格式
	// 会被显示传入的SecretKey所覆盖
	ENV_APOLLO_SECRET_KEY = "APOLLO_SECRET_KEY"

	// ENV_HEADER_ENCRYPT_FLAG 默认从环境变量读取，根据header附带的标志判断body是否加密
	ENV_HEADER_ENCRYPT_FLAG = "HEADER_ENCRYPT_FLAG"
)

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type apolloClient struct {
	Doer          Doer
	IP            string
	ConfigType    string // 默认properties不需要在namespace后加后缀名，其他情况例如application.json {xml,yml,yaml,json,...}
	AccessKey     string
	SecretKey     string
	EncryptFlag   string
	SignatureFunc SignatureFunc
}

func NewApolloClient(opts ...ApolloClientOption) ApolloClient {
	c := &apolloClient{
		IP:         getLocalIP(),
		ConfigType: defaultConfigType,
		Doer: &http.Client{
			Timeout: defaultClientTimeout, // Notifications由于服务端会hold住请求60秒，所以请确保客户端访问服务端的超时时间要大于60秒。
		},
		AccessKey:     os.Getenv(ENV_APOLLO_ACCESS_KEY),
		SecretKey:     os.Getenv(ENV_APOLLO_SECRET_KEY),
		EncryptFlag:   os.Getenv(ENV_HEADER_ENCRYPT_FLAG),
		SignatureFunc: DefaultSignatureFunc,
	}

	c.Apply(opts...)

	return c
}

func (c *apolloClient) Apply(opts ...ApolloClientOption) {
	for _, opt := range opts {
		opt(c)
	}
}

func (c *apolloClient) Notifications(configServerURL, appID, cluster string, notifications []Notification) (status int, result []Notification, err error) {
	if len(notifications) == 0 {
		return 0, []Notification{}, nil
	}
	configServerURL = normalizeURL(configServerURL)
	requestURI := fmt.Sprintf("/notifications/v2?appId=%s&cluster=%s&notifications=%s",
		url.QueryEscape(appID),
		url.QueryEscape(cluster),
		url.QueryEscape(Notifications(notifications).String()),
	)
	apiURL := fmt.Sprintf("%s%s", configServerURL, requestURI)

	headers := c.SignatureFunc(&SignatureContext{
		ConfigServerURL: configServerURL,
		RequestURI:      requestURI,
		AccessKey:       c.AccessKey,
		AppID:           appID,
		Cluster:         cluster,
	})
	status, err = c.do("GET", apiURL, headers, &result)
	return
}

func (c *apolloClient) GetConfigsFromNonCache(configServerURL, appID, cluster, namespace string, opts ...NotificationsOption) (status int, config *Config, err error) {
	var options = NotificationsOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	configServerURL = normalizeURL(configServerURL)
	requestURI := fmt.Sprintf("/configs/%s/%s/%s?releaseKey=%s&ip=%s",
		url.QueryEscape(appID),
		url.QueryEscape(cluster),
		url.QueryEscape(c.getNamespace(namespace)),
		options.ReleaseKey,
		c.IP,
	)
	apiURL := fmt.Sprintf("%s%s", configServerURL, requestURI)

	headers := c.SignatureFunc(&SignatureContext{
		ConfigServerURL: configServerURL,
		RequestURI:      requestURI,
		AccessKey:       c.AccessKey,
		AppID:           appID,
		Cluster:         cluster,
	})
	config = new(Config)
	status, err = c.do("GET", apiURL, headers, config)
	return

}

func (c *apolloClient) GetConfigsFromCache(configServerURL, appID, cluster, namespace string) (config Configurations, err error) {
	configServerURL = normalizeURL(configServerURL)
	requestURI := fmt.Sprintf("/configfiles/json/%s/%s/%s?ip=%s",
		url.QueryEscape(appID),
		url.QueryEscape(cluster),
		url.QueryEscape(c.getNamespace(namespace)),
		c.IP,
	)
	apiURL := fmt.Sprintf("%s%s", configServerURL, requestURI)

	headers := c.SignatureFunc(&SignatureContext{
		ConfigServerURL: configServerURL,
		RequestURI:      requestURI,
		AccessKey:       c.AccessKey,
		AppID:           appID,
		Cluster:         cluster,
	})
	config = make(Configurations)
	_, err = c.do("GET", apiURL, headers, config)
	return
}

func (c *apolloClient) GetConfigServers(metaServerURL, appID string) (int, []ConfigServer, error) {
	metaServerURL = normalizeURL(metaServerURL)
	requestURI := fmt.Sprintf("/services/config?id=%s&appId=%s", c.IP, appID)
	apiURL := fmt.Sprintf("%s%s", metaServerURL, requestURI)

	headers := c.SignatureFunc(&SignatureContext{
		ConfigServerURL: metaServerURL,
		RequestURI:      requestURI,
		AccessKey:       c.AccessKey,
		AppID:           appID,
		Cluster:         "",
	})
	var cfs []ConfigServer
	status, err := c.do("GET", apiURL, headers, &cfs)
	return status, cfs, err
}

func (c *apolloClient) do(method, url string, headers map[string]string, v interface{}) (status int, err error) {
	var req *http.Request
	req, err = http.NewRequest(method, url, nil)
	if err != nil {
		return
	}

	for key, val := range headers {
		req.Header.Set(key, val)
	}

	var body []byte
	status, body, err = c.parseResponseBody(c.Doer, req)
	if err != nil {
		return
	}

	if status == http.StatusOK {
		err = json.Unmarshal(body, v)
	}
	return
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

// 配置文件有多种格式，例如：properties、xml、yml、yaml、json等。同样Namespace也具有这些格式。在Portal UI中可以看到“application”的Namespace上有一个“properties”标签，表明“application”是properties格式的。
// 如果使用Http接口直接调用时，对应的namespace参数需要传入namespace的名字加上后缀名，如datasources.json。
func (c *apolloClient) getNamespace(namespace string) string {
	if c.ConfigType == "" || c.ConfigType == defaultConfigType {
		return namespace
	}
	return namespace + "." + c.ConfigType
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func (c *apolloClient) parseResponseBody(doer Doer, req *http.Request) (int, []byte, error) {
	resp, err := doer.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	// if encrypted, decrypt
	if resp.Header.Get(c.EncryptFlag) == "true" {
		raw, err := base64.RawStdEncoding.DecodeString(c.SecretKey)
		if err != nil {
			return 0, nil, err
		}

		sk, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return 0, nil, err
		}

		privKey := sk.(*rsa.PrivateKey)
		partLen := privKey.PublicKey.N.BitLen() / 8
		chunks := split(body, partLen)
		buffer := bytes.NewBufferString("")
		for _, chunk := range chunks {
			decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, chunk)
			if err != nil {
				return 0, nil, err
			}
			buffer.Write(decrypted)
		}
		return resp.StatusCode, buffer.Bytes(), nil
	}

	return resp.StatusCode, body, nil
}

package gorilla

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/mkawserm/abesh/iface"
	"github.com/mkawserm/abesh/logger"
	"github.com/mkawserm/abesh/model"
	"github.com/mkawserm/abesh/registry"
	"github.com/mkawserm/abesh/utility"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var ErrPathNotDefined = errors.New("path not defined")
var ErrMethodNotDefined = errors.New("method not defined")

type EventResponse struct {
	Error error
	Event *model.Event
}

var responseStatus = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "abesh_httpserver_response_status",
		Help: "Status of HTTP Response",
	},
	[]string{"trigger", "service", "path", "method", "status"},
)

type HttpServerGorilla struct {
	mCM                       model.ConfigMap
	mHost                     string
	mPort                     string
	mKeyFile                  string
	mCertFile                 string
	mStaticDir                string
	mStaticPath               string
	mHealthPath               string
	mMetricPath               string
	mIsMetricsEnabled         bool
	mHttpServer               *http.Server
	mHttpServerMux            *mux.Router
	mRequestTimeout           time.Duration
	mEventTransmitter         iface.IEventTransmitter
	mDefaultContentType       string
	mEmbeddedStaticFSMap      map[string]embed.FS
	mDefault404HandlerEnabled bool
	mDefault405HandlerEnabled bool
	mHandleMethodNotAllowed   bool

	/* Default Http Responses */
	d401m string
	d403m string
	d404m string
	d405m string
	d408m string
	d409m string
	d499m string
	d500m string
}

func (h *HttpServerGorilla) Name() string {
	return Name
}

func (h *HttpServerGorilla) Version() string {
	return Version
}

func (h *HttpServerGorilla) Category() string {
	return Category
}

func (h *HttpServerGorilla) ContractId() string {
	return ContractId
}

func (h *HttpServerGorilla) New() iface.ICapability {
	return &HttpServerGorilla{}
}

func (h *HttpServerGorilla) SetConfigMap(cm model.ConfigMap) error {
	h.mCM = cm
	h.mHost = cm.String("host", "0.0.0.0")
	h.mPort = cm.String("port", "8080")

	h.mCertFile = cm.String("cert_file", "")
	h.mKeyFile = cm.String("key_file", "")

	h.mStaticDir = cm.String("static_dir", "")
	h.mStaticPath = cm.String("static_path", "/static/")
	h.mHealthPath = cm.String("health_path", "")

	if !strings.HasSuffix(h.mStaticPath, "/") && len(h.mStaticPath) > 0 {
		h.mStaticPath = h.mStaticPath + "/"
	}

	h.mRequestTimeout = cm.Duration("default_request_timeout", time.Second)

	h.mDefault404HandlerEnabled = cm.Bool("default_404_handler_enabled", true)
	h.mDefault405HandlerEnabled = cm.Bool("default_405_handler_enabled", true)
	h.mHandleMethodNotAllowed = cm.Bool("handle_method_not_allowed", false)

	h.mDefaultContentType = cm.String("default_content_type", "application/json")

	h.mIsMetricsEnabled = cm.Bool("metrics_enabled", false)
	h.mMetricPath = cm.String("metric_path", "/metrics")

	h.d401m = h.buildDefaultMessage(401)
	h.d403m = h.buildDefaultMessage(403)
	h.d404m = h.buildDefaultMessage(404)
	h.d405m = h.buildDefaultMessage(405)
	h.d408m = h.buildDefaultMessage(408)
	h.d409m = h.buildDefaultMessage(409)
	h.d499m = h.buildDefaultMessage(499)
	h.d500m = h.buildDefaultMessage(500)

	return nil
}

func (h *HttpServerGorilla) GetConfigMap() model.ConfigMap {
	return h.mCM
}

func (h *HttpServerGorilla) Setup() error {
	h.mHttpServer = new(http.Server)
	h.mHttpServerMux = mux.NewRouter()
	h.mEmbeddedStaticFSMap = make(map[string]embed.FS)

	// setup server details
	h.mHttpServer.Handler = h.mHttpServerMux
	h.mHttpServer.Addr = h.mHost + ":" + h.mPort

	if h.mDefault405HandlerEnabled {
		logger.L(h.ContractId()).Debug("default 405 handler enabled")
		handler405 := func(writer http.ResponseWriter, request *http.Request) {
			h.debugMessage(request)
			timerStart := time.Now()
			defer func() {
				logger.L(h.ContractId()).Debug("request completed")
				elapsed := time.Since(timerStart)
				logger.L(h.ContractId()).Debug("request execution time",
					zap.Duration("seconds", elapsed))
			}()
			h.s405m(request, writer, nil)
			return
		}
		h.mHttpServerMux.MethodNotAllowedHandler = http.HandlerFunc(handler405)
	}

	if h.mDefault404HandlerEnabled {
		logger.L(h.ContractId()).Debug("default 404 handler enabled")
		handler404 := func(writer http.ResponseWriter, request *http.Request) {
			h.debugMessage(request)
			timerStart := time.Now()
			defer func() {
				logger.L(h.ContractId()).Debug("request completed")
				elapsed := time.Since(timerStart)
				logger.L(h.ContractId()).Debug("request execution time", zap.Duration("seconds", elapsed))
			}()
			h.s404m(request, writer, nil)
			return
		}
		h.mHttpServerMux.NotFoundHandler = http.HandlerFunc(handler404)
	}

	// register data path
	if len(h.mStaticDir) != 0 {
		fi, e := os.Stat(h.mStaticDir)
		if e != nil {
			logger.L(h.ContractId()).Error(e.Error())
		} else {
			if fi.IsDir() {
				logger.L(h.ContractId()).Debug("data path", zap.String("static_path", h.mStaticPath))
				fs := http.FileServer(http.Dir(h.mStaticDir))
				h.mHttpServerMux.PathPrefix(h.mStaticPath).Handler(http.StripPrefix(h.mStaticPath, fs))
			} else {
				logger.L(h.ContractId()).Error("provided static_dir in the manifest conf is not directory")
			}
		}
	}

	// register health path
	if len(h.mHealthPath) != 0 {
		h.mHttpServerMux.
			Methods("GET").
			Path(h.mHealthPath).
			HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusOK)
				logger.L(h.ContractId()).Info("HEALTH OK")
			})
	}

	if h.mIsMetricsEnabled {
		h.AddHandler(h.mMetricPath, promhttp.Handler())
		logger.L(h.ContractId()).Info("metrics enabled", zap.String("metric_path", h.mMetricPath))
	}

	logger.L(h.ContractId()).Info("http server setup complete",
		zap.String("host", h.mHost),
		zap.String("port", h.mPort))

	return nil
}

func (h *HttpServerGorilla) Start(context.Context) error {
	logger.L(h.ContractId()).Debug("registering embedded data fs")
	for p, d := range h.mEmbeddedStaticFSMap {
		if !strings.HasSuffix(p, "/") {
			p = p + "/"
		}
		h.ServeFiles(p, http.FS(d))
	}

	logger.L(h.ContractId()).Info("http server started at " + h.mHttpServer.Addr)

	if len(h.mCertFile) != 0 && len(h.mKeyFile) != 0 {
		if err := h.mHttpServer.ListenAndServeTLS(h.mCertFile, h.mKeyFile); err != http.ErrServerClosed {
			return err
		}
	} else {
		if err := h.mHttpServer.ListenAndServe(); err != http.ErrServerClosed {
			return err
		}
	}

	return nil
}

func (h *HttpServerGorilla) Stop(ctx context.Context) error {
	if h.mHttpServer != nil {
		return h.mHttpServer.Shutdown(ctx)
	}
	return nil
}

func (h *HttpServerGorilla) SetEventTransmitter(eventTransmitter iface.IEventTransmitter) error {
	h.mEventTransmitter = eventTransmitter
	return nil
}

func (h *HttpServerGorilla) GetEventTransmitter() iface.IEventTransmitter {
	return h.mEventTransmitter
}

func (h *HttpServerGorilla) TransmitInputEvent(contractId string, event *model.Event) error {
	if h.GetEventTransmitter() != nil {
		go func() {
			var err = h.GetEventTransmitter().TransmitInputEvent(contractId, event)
			if err != nil {
				logger.L(h.ContractId()).Error(err.Error(),
					zap.String("version", h.Version()),
					zap.String("name", h.Name()),
					zap.String("contract_id", h.ContractId()))
			}

		}()
	}
	return nil
}

func (h *HttpServerGorilla) TransmitOutputEvent(contractId string, event *model.Event) error {
	if h.GetEventTransmitter() != nil {
		go func() {
			err := h.GetEventTransmitter().TransmitOutputEvent(contractId, event)
			if err != nil {
				logger.L(h.ContractId()).Error(err.Error(),
					zap.String("version", h.Version()),
					zap.String("name", h.Name()),
					zap.String("contract_id", h.ContractId()))
			}
		}()
	}
	return nil
}

func (h *HttpServerGorilla) buildDefaultMessage(code uint32) string {
	return fmt.Sprintf(`
		{
			"code": "SE_%d",
			"lang": "en",
			"message": "%d ERROR",
			"data": {}
		}
	`, code, code)
}

func (h *HttpServerGorilla) getMessage(key, defaultValue, lang string) string {
	var data = h.mCM.String(fmt.Sprintf("%s_%s", key, lang), "")
	if len(data) == 0 {
		data = h.mCM.String(key, defaultValue)
	}
	return data
}

func (h *HttpServerGorilla) getLanguage(r *http.Request) string {
	var l = r.Header.Get("Accept-Language")
	if len(l) == 0 {
		l = "en"
	}
	return l
}

func (h *HttpServerGorilla) AddEmbeddedStaticFS(pattern string, fs embed.FS) {
	// NOTE: must be called after setup otherwise panic will occur
	h.mEmbeddedStaticFSMap[pattern] = fs
}

func (h *HttpServerGorilla) writeMessage(statusCode int, defaultMessage string, request *http.Request, writer http.ResponseWriter, errLocal error) {
	if errLocal != nil {
		logger.L(h.ContractId()).Error(errLocal.Error(),
			zap.String("version", h.Version()),
			zap.String("name", h.Name()),
			zap.String("contract_id", h.ContractId()))
	}

	writer.Header().Add("Content-Type", h.mDefaultContentType)
	writer.WriteHeader(statusCode)
	if _, err := writer.Write([]byte(h.getMessage(fmt.Sprintf("s%dm", statusCode), defaultMessage, h.getLanguage(request)))); err != nil {
		logger.L(h.ContractId()).Error(err.Error(),
			zap.String("version", h.Version()),
			zap.String("name", h.Name()),
			zap.String("contract_id", h.ContractId()))
	}
}

func (h *HttpServerGorilla) s401m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	responseStatus.WithLabelValues(h.ContractId(), "", request.URL.Path, request.Method, "401").Inc()
	h.writeMessage(401, h.d401m, request, writer, errLocal)
}

func (h *HttpServerGorilla) s403m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	responseStatus.WithLabelValues(h.ContractId(), "", request.URL.Path, request.Method, "403").Inc()
	h.writeMessage(403, h.d403m, request, writer, errLocal)
}

func (h *HttpServerGorilla) s404m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	responseStatus.WithLabelValues(h.ContractId(), "", request.URL.Path, request.Method, "404").Inc()
	h.writeMessage(404, h.d404m, request, writer, errLocal)
}

func (h *HttpServerGorilla) s405m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	responseStatus.WithLabelValues(h.ContractId(), "", request.URL.Path, request.Method, "405").Inc()
	h.writeMessage(405, h.d405m, request, writer, errLocal)
}

func (h *HttpServerGorilla) s408m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	responseStatus.WithLabelValues(h.ContractId(), "", request.URL.Path, request.Method, "408").Inc()
	h.writeMessage(408, h.d408m, request, writer, errLocal)
}

func (h *HttpServerGorilla) s499m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	responseStatus.WithLabelValues(h.ContractId(), "", request.URL.Path, request.Method, "499").Inc()
	h.writeMessage(499, h.d499m, request, writer, errLocal)
}

func (h *HttpServerGorilla) s500m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	responseStatus.WithLabelValues(h.ContractId(), "", request.URL.Path, request.Method, "500").Inc()
	h.writeMessage(500, h.d500m, request, writer, errLocal)
}

func (h *HttpServerGorilla) ServeFiles(path string, root http.FileSystem) {
	var fileServer = http.FileServer(root)
	h.mHttpServerMux.Methods("GET").PathPrefix(path).Handler(http.StripPrefix(path, fileServer))
}

func (h *HttpServerGorilla) debugMessage(request *http.Request) {
	logger.L(h.ContractId()).Debug("request local timeout in seconds", zap.Duration("timeout", h.mRequestTimeout))
	logger.L(h.ContractId()).Debug("request started")
	logger.L(h.ContractId()).Debug("request data",
		zap.String("path", request.URL.Path),
		zap.String("method", request.Method),
		zap.String("path_with_query", request.RequestURI))
}

func (h *HttpServerGorilla) AddHandlerFunc(pattern string, handler http.HandlerFunc) {
	h.mHttpServerMux.HandleFunc(pattern, handler)
}

func (h *HttpServerGorilla) AddHandler(pattern string, handler http.Handler) {
	h.mHttpServerMux.Handle(pattern, handler)
}

func (h *HttpServerGorilla) AddService(
	authorizer iface.IAuthorizer,
	authorizerExpression string,
	triggerValues model.ConfigMap,
	service iface.IService,
) error {
	var methodString string
	var path string
	var methodList []string

	// url http access method
	if methodString = triggerValues.String("method", ""); len(methodString) == 0 {
		return ErrMethodNotDefined
	}
	methodString = strings.ToUpper(strings.TrimSpace(methodString))
	methodList = strings.Split(methodString, ",")
	if len(methodList) > 0 {
		sort.Strings(methodList)
	}

	// url http path
	if path = triggerValues.String("path", ""); len(path) == 0 {
		return ErrPathNotDefined
	}
	path = strings.TrimSpace(path)

	requestHandler := func(writer http.ResponseWriter, request *http.Request) {
		var err error
		timerStart := time.Now()

		defer func() {
			logger.L(h.ContractId()).Debug("request completed")
			elapsed := time.Since(timerStart)
			logger.L(h.ContractId()).Debug("request execution time", zap.Duration("seconds", elapsed))
		}()

		h.debugMessage(request)

		if !utility.IsIn(methodList, request.Method) {
			h.s405m(request, writer, nil)
			return
		}

		var data []byte
		var headers = make(map[string]string)
		var metadata = &model.Metadata{}

		metadata.Method = request.Method
		metadata.Path = request.URL.EscapedPath()
		metadata.Headers = make(map[string]string)
		metadata.Query = make(map[string]string)
		metadata.Params = make(map[string]string)
		metadata.ContractIdList = append(metadata.ContractIdList, h.ContractId())
		for k, v := range mux.Vars(request) {
			metadata.Params[k] = v
		}

		for k, v := range request.Header {
			if len(v) > 0 {
				metadata.Headers[k] = v[0]
				headers[strings.ToLower(strings.TrimSpace(k))] = v[0]
			}
		}

		for k, v := range request.URL.Query() {
			if len(v) > 0 {
				metadata.Query[k] = v[0]
			}
		}

		logger.L(h.ContractId()).Debug("request params",
			zap.Any("params", metadata.Params))

		if authorizer != nil {
			if !authorizer.IsAuthorized(authorizerExpression, metadata) {
				h.s403m(request, writer, nil)
				return
			}
		}

		if data, err = ioutil.ReadAll(request.Body); err != nil {
			h.s500m(request, writer, err)
			return
		}

		inputEvent := &model.Event{
			Metadata: metadata,
			TypeUrl:  utility.GetValue(headers, "content-type", "application/text"),
			Value:    data,
		}

		// transmit input event
		err = h.TransmitInputEvent(service.ContractId(), inputEvent)
		if err != nil {
			logger.L(h.ContractId()).Error(err.Error())
		}

		nCtx, cancel := context.WithTimeout(request.Context(), h.mRequestTimeout)
		defer cancel()

		ch := make(chan EventResponse, 1)

		func() {
			if request.Context().Err() != nil {
				ch <- EventResponse{
					Event: nil,
					Error: request.Context().Err(),
				}
			} else {
				go func() {
					event, errInner := service.Serve(nCtx, inputEvent)
					ch <- EventResponse{Event: event, Error: errInner}
				}()
			}
		}()

		select {
		case <-nCtx.Done():
			h.s408m(request, writer, nil)
			return
		case r := <-ch:
			if r.Error == context.DeadlineExceeded {
				h.s408m(request, writer, r.Error)
				return
			}

			if r.Error == context.Canceled {
				h.s499m(request, writer, r.Error)
				return
			}

			if r.Error != nil {
				h.s500m(request, writer, r.Error)
				return
			}

			// NOTE: PROMETHEUS RESPONSE STATISTICS
			go func() {
				responseStatus.WithLabelValues(
					h.ContractId(),
					service.ContractId(),
					request.URL.Path,
					request.Method,
					fmt.Sprintf("%d", r.Event.Metadata.StatusCode),
				).Inc()
			}()

			// transmit output event
			err = h.TransmitOutputEvent(service.ContractId(), r.Event)
			if err != nil {
				logger.L(h.ContractId()).Error(err.Error())
			}

			// NOTE: handle success from service
			for k, v := range r.Event.Metadata.Headers {
				writer.Header().Add(k, v)
			}

			writer.WriteHeader(int(r.Event.Metadata.StatusCode))

			if _, err = writer.Write(r.Event.Value); err != nil {
				logger.L(h.ContractId()).Error(err.Error(),
					zap.String("version", h.Version()),
					zap.String("name", h.Name()),
					zap.String("contract_id", h.ContractId()))
			}
		}
	}

	h.mHttpServerMux.Methods(methodList...).Path(path).HandlerFunc(requestHandler)

	return nil
}

func init() {
	prometheus.MustRegister(responseStatus)
	registry.GlobalRegistry().AddCapability(&HttpServerGorilla{})
}

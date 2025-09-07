package logger

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

type Stack struct {
	Status     string `json:"status,omitempty"`
	ResultType string `json:"resultType,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Message    string `json:"message,omitempty"`
	Code       string `json:"code,omitempty"`
}

type SummaryLogService interface {
	Init(data LogDto)
	Update(key string, value any)
	Flush(data Stack)
}
type summaryLogService struct {
	logDto         LogDto
	logger         LoggerService
	maskingService MaskingServiceInterface
	customLogger   *customLoggerService
}

func NewSummaryLogService(logger LoggerService, customLogger *customLoggerService, maskingService MaskingServiceInterface) SummaryLogService {
	return &summaryLogService{
		logger:         logger,
		maskingService: maskingService,
		customLogger:   customLogger,
		logDto:         customLogger.logDto,
	}
}

func (s *summaryLogService) Init(data LogDto) {
	s.logDto = data
}
func (s *summaryLogService) Update(key string, value any) {
	v := reflect.ValueOf(&s.logDto).Elem()
	field := v.FieldByName(key)
	if field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(value))
	}
}
func (s *summaryLogService) Flush(data Stack) {
	s.Init(s.logDto)
	if s.logDto.CustomFields == nil {
		s.logDto.CustomFields = make(map[string]any)
	}
	s.logDto.LogType = "summary"
	s.logDto.ResponseTime = time.Since(s.customLogger.utilService.begin).Microseconds()

	if data.Code != "" {
		s.logDto.AppResultCode = data.Code
	} else {
		if s.customLogger.logDto.AppResultCode != "" {
			s.logDto.AppResultCode = s.customLogger.logDto.AppResultCode
		} else {
			s.logDto.AppResultCode = "20000"
		}
	}

	if data.Status != "" {
		s.logDto.AppResultHttpStatus = data.Status
	} else {
		if s.customLogger.logDto.AppResultHttpStatus != "" {
			s.logDto.AppResultHttpStatus = s.customLogger.logDto.AppResultHttpStatus
		} else {
			s.logDto.AppResultHttpStatus = "200"
		}
	}

	if s.customLogger.logDto.AppResultType != "" {
		s.logDto.AppResultType = s.customLogger.logDto.AppResultType
	} else {
		s.logDto.AppResultType = HEALTHY
	}

	if s.customLogger.logDto.Severity != "" {
		s.logDto.Severity = s.customLogger.logDto.Severity
	} else {
		s.logDto.Severity = NORMAL
	}

	if data.ResultType != "" {
		if strings.ToLower(data.ResultType) == "ok" {
			s.logDto.AppResult = "Success"
		} else {
			s.logDto.AppResult = data.ResultType
		}
	} else {
		if s.customLogger.logDto.AppResult != "" {
			s.logDto.AppResult = s.customLogger.logDto.AppResult
		} else {
			s.logDto.AppResult = "Success"
		}
	}

	if len(s.customLogger.summaryLogAdditionalInfo) > 0 {
		s.logDto.Sequences = append(s.logDto.Sequences, s.customLogger.summaryLogAdditionalInfo...)
		sequences := s.logDto.Sequences
		events := []EventSummary{}
		for i := range sequences {
			events = append(events, EventSummary{
				Event:  sequences[i].Node + "." + sequences[i].Command,
				Result: sequences[i].Result,
			})
		}

		s.logDto.Sequences = nil
		sequences = nil
		s.logDto.Flow = events
		s.customLogger.summaryLogAdditionalInfo = nil
	}

	if len(s.customLogger.additionalSummary) > 0 {
		for key, value := range s.customLogger.additionalSummary {
			s.logDto.CustomFields[key] = value // fix bug
		}
	}

	s.clearNonSummaryLogParam()
	s.logDto.ThreadId = getGoroutineID()
	jsonBytes, err := json.Marshal(s.logDto)
	if err == nil {
		info := string(jsonBytes)
		s.logger.Info(info)
	}
	s.customLogger = nil
	s.logDto = LogDto{}
}

func (c *summaryLogService) clearNonSummaryLogParam() {
	c.logDto.Action = ""
	// c.logDto.Message = ""
	c.logDto.Timestamp = nil
	c.logDto.ActionDescription = ""
	c.logDto.SubAction = ""
	c.logDto.Metadata = Metadata{}
}

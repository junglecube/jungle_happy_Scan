package httpraw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

type jsonScanner struct {
	data   []byte
	index  int
	points []InsertionPoint
}

func discoverJSONPoints(data []byte) ([]InsertionPoint, error) {
	scanner := &jsonScanner{data: data}
	if err := scanner.value(""); err != nil {
		return nil, err
	}
	scanner.space()
	if scanner.index != len(data) {
		return nil, fmt.Errorf("JSON 顶层值后存在多余数据")
	}
	return scanner.points, nil
}

func (s *jsonScanner) value(path string) error {
	s.space()
	if s.index >= len(s.data) {
		return fmt.Errorf("JSON 值缺失")
	}
	switch s.data[s.index] {
	case '{':
		return s.object(path)
	case '[':
		return s.array(path)
	case '"':
		start := s.index
		value, err := s.stringValue()
		if err != nil {
			return err
		}
		s.add(path, value, "string", start, s.index)
		return nil
	case 't', 'f':
		start := s.index
		literal := "true"
		if s.data[s.index] == 'f' {
			literal = "false"
		}
		if !s.consume(literal) {
			return fmt.Errorf("JSON 布尔值无效")
		}
		s.add(path, literal, "bool", start, s.index)
		return nil
	case 'n':
		start := s.index
		if !s.consume("null") {
			return fmt.Errorf("JSON null 无效")
		}
		s.add(path, "", "null", start, s.index)
		return nil
	default:
		start := s.index
		for s.index < len(s.data) && !bytes.ContainsRune([]byte(" \t\r\n,]}"), rune(s.data[s.index])) {
			s.index++
		}
		raw := s.data[start:s.index]
		if len(raw) == 0 || !json.Valid(raw) {
			return fmt.Errorf("JSON 数字无效")
		}
		s.add(path, string(raw), "number", start, s.index)
		return nil
	}
}

func (s *jsonScanner) object(path string) error {
	s.index++
	s.space()
	if s.take('}') {
		return nil
	}
	for {
		s.space()
		if s.index >= len(s.data) || s.data[s.index] != '"' {
			return fmt.Errorf("JSON 对象 Key 无效")
		}
		key, err := s.stringValue()
		if err != nil {
			return err
		}
		s.space()
		if !s.take(':') {
			return fmt.Errorf("JSON 对象缺少冒号")
		}
		next := key
		if path != "" {
			next = path + "." + key
		}
		if err := s.value(next); err != nil {
			return err
		}
		s.space()
		if s.take('}') {
			return nil
		}
		if !s.take(',') {
			return fmt.Errorf("JSON 对象缺少逗号")
		}
	}
}

func (s *jsonScanner) array(path string) error {
	s.index++
	s.space()
	if s.take(']') {
		return nil
	}
	for index := 0; ; index++ {
		next := fmt.Sprintf("%s[%d]", path, index)
		if err := s.value(next); err != nil {
			return err
		}
		s.space()
		if s.take(']') {
			return nil
		}
		if !s.take(',') {
			return fmt.Errorf("JSON 数组缺少逗号")
		}
	}
}

func (s *jsonScanner) stringValue() (string, error) {
	start := s.index
	s.index++
	escaped := false
	for s.index < len(s.data) {
		current := s.data[s.index]
		s.index++
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if current == '"' {
			var value string
			if err := json.Unmarshal(s.data[start:s.index], &value); err != nil {
				return "", err
			}
			return value, nil
		}
	}
	return "", fmt.Errorf("JSON 字符串未闭合")
}

func (s *jsonScanner) add(path, value, valueType string, start, end int) {
	s.points = append(s.points, InsertionPoint{
		Location: "json", Name: leafName(path), Path: path, Value: value,
		ValueType: valueType, start: start, end: end,
	})
}

func (s *jsonScanner) space() {
	for s.index < len(s.data) && bytes.ContainsRune([]byte(" \t\r\n"), rune(s.data[s.index])) {
		s.index++
	}
}

func (s *jsonScanner) take(value byte) bool {
	if s.index < len(s.data) && s.data[s.index] == value {
		s.index++
		return true
	}
	return false
}

func (s *jsonScanner) consume(value string) bool {
	if !bytes.HasPrefix(s.data[s.index:], []byte(value)) {
		return false
	}
	s.index += len(value)
	return true
}

func encodeJSONMutation(value, valueType string) ([]byte, error) {
	switch valueType {
	case "number":
		if _, err := strconv.ParseFloat(value, 64); err == nil && json.Valid([]byte(value)) {
			return []byte(value), nil
		}
	case "bool":
		if value == "true" || value == "false" {
			return []byte(value), nil
		}
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

func replaceJSONPoint(body []byte, point InsertionPoint, replacement []byte) ([]byte, error) {
	target := point
	if target.start < 0 || target.end <= target.start || target.end > len(body) {
		points, err := discoverJSONPoints(body)
		if err != nil {
			return nil, err
		}
		found := false
		for _, candidate := range points {
			if candidate.Path == point.Path {
				target = candidate
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("JSON 字段 %q 不存在", point.Path)
		}
	}
	result := make([]byte, 0, len(body)-target.end+target.start+len(replacement))
	result = append(result, body[:target.start]...)
	result = append(result, replacement...)
	result = append(result, body[target.end:]...)
	return result, nil
}

package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"jungle_happy_Scan/internal/clientcert"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
	"jungle_happy_Scan/internal/transport"
)

const (
	MaxReplayConcurrency = 100
	MaxReplayRequests    = 20_000
	MaxReplayDictionary  = 20_000
)

var replayPlaceholderPattern = regexp.MustCompile(`\{\{(?:(int|integer)\(([0-9]+)-([0-9]+)\)|([A-Za-z_][A-Za-z0-9_.-]*)\(dict\))\}\}`)

type ReplayVariant struct {
	Index   int
	RawHTTP string
	Payload string
}

type ReplayOptions struct {
	Concurrency int
	Repeat      int
	MaxRequests int
	Dictionary  []string
}

type ReplayResult struct {
	Index             int
	Payload           string
	StatusCode        int
	ResponseBytes     int64
	CapturedBytes     int
	ElapsedMS         int64
	Scheme            string
	Error             string
	RawResponse       string
	ResponseTruncated bool
}

type replayGenerator struct {
	token  string
	label  string
	values []string
}

// ExpandReplayTemplate expands integer and one-line dictionary placeholders.
// Repeated occurrences of the same placeholder receive the same value. When
// multiple independent generators are present, their bounded Cartesian product
// is generated in deterministic left-to-right order.
func ExpandReplayTemplate(raw string, options ReplayOptions) ([]ReplayVariant, bool, error) {
	if len(raw) < 10 {
		return nil, false, errors.New("http 字段必须包含完整 HTTP 报文")
	}
	if options.Repeat == 0 {
		options.Repeat = 10
	}
	if options.Repeat < 1 || options.Repeat > MaxReplayRequests {
		return nil, false, fmt.Errorf("repeat 必须在 1 到 %d 之间", MaxReplayRequests)
	}
	if options.MaxRequests == 0 {
		options.MaxRequests = 10_000
	}
	if options.MaxRequests < 1 || options.MaxRequests > MaxReplayRequests {
		return nil, false, fmt.Errorf("max_requests 必须在 1 到 %d 之间", MaxReplayRequests)
	}
	if len(options.Dictionary) > MaxReplayDictionary {
		return nil, false, fmt.Errorf("字典最多允许 %d 个非空条目", MaxReplayDictionary)
	}

	matches := replayPlaceholderPattern.FindAllStringSubmatch(raw, -1)
	if len(matches) == 0 {
		result := make([]ReplayVariant, options.Repeat)
		for index := range result {
			result[index] = ReplayVariant{Index: index + 1, RawHTTP: raw, Payload: fmt.Sprintf("重复请求 #%d", index+1)}
		}
		return result, false, nil
	}

	dictionary := make([]string, 0, len(options.Dictionary))
	for _, item := range options.Dictionary {
		item = strings.TrimSuffix(strings.TrimSuffix(item, "\n"), "\r")
		if item == "" {
			continue
		}
		if len(item) > 16_384 {
			return nil, false, errors.New("单个字典项不能超过 16384 字节")
		}
		dictionary = append(dictionary, item)
	}
	generators := make([]replayGenerator, 0)
	seen := make(map[string]bool)
	for _, match := range matches {
		token := match[0]
		if seen[token] {
			continue
		}
		seen[token] = true
		if match[4] != "" {
			if len(dictionary) == 0 {
				return nil, false, fmt.Errorf("%s 需要上传非空 TXT 字典", token)
			}
			generators = append(generators, replayGenerator{token: token, label: match[4] + "(dict)", values: dictionary})
			continue
		}
		minimum, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("%s 的最小值无效", token)
		}
		maximum, err := strconv.ParseUint(match[3], 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("%s 的最大值无效", token)
		}
		if minimum > maximum {
			return nil, false, fmt.Errorf("%s 的最小值不能大于最大值", token)
		}
		if maximum-minimum >= MaxReplayRequests {
			return nil, false, fmt.Errorf("%s 的整数范围超过 %d", token, MaxReplayRequests)
		}
		width := 0
		if (len(match[2]) > 1 && strings.HasPrefix(match[2], "0")) || (len(match[3]) > 1 && strings.HasPrefix(match[3], "0")) {
			width = max(len(match[2]), len(match[3]))
		}
		values := make([]string, 0, int(maximum-minimum+1))
		for value := minimum; value <= maximum; value++ {
			if width > 0 {
				values = append(values, fmt.Sprintf("%0*d", width, value))
			} else {
				values = append(values, strconv.FormatUint(value, 10))
			}
		}
		generators = append(generators, replayGenerator{token: token, label: match[1] + "(" + match[2] + "-" + match[3] + ")", values: values})
	}

	variants := []ReplayVariant{{RawHTTP: raw}}
	truncated := false
	for _, generator := range generators {
		next := make([]ReplayVariant, 0, min(options.MaxRequests, len(variants)*len(generator.values)))
		for _, base := range variants {
			for _, value := range generator.values {
				payload := generator.label + "=" + value
				if base.Payload != "" {
					payload = base.Payload + "; " + payload
				}
				next = append(next, ReplayVariant{
					RawHTTP: strings.ReplaceAll(base.RawHTTP, generator.token, value),
					Payload: payload,
				})
				if len(next) == options.MaxRequests {
					truncated = true
					break
				}
			}
			if len(next) == options.MaxRequests {
				break
			}
		}
		variants = next
	}
	for index := range variants {
		variants[index].Index = index + 1
	}
	return variants, truncated, nil
}

// RunReplayVariants executes an already-expanded bounded request set. The
// configured process and per-host governors still apply, so this high
// concurrency feature cannot bypass global safety limits.
func (m *Manager) RunReplayVariants(
	ctx context.Context,
	input model.ScanInput,
	variants []ReplayVariant,
	concurrency int,
	onResult func(ReplayResult),
) error {
	if len(variants) == 0 || len(variants) > MaxReplayRequests {
		return fmt.Errorf("爆破请求数量必须在 1 到 %d 之间", MaxReplayRequests)
	}
	if concurrency < 1 || concurrency > MaxReplayConcurrency {
		return fmt.Errorf("concurrency 必须在 1 到 %d 之间", MaxReplayConcurrency)
	}
	cfg := m.store.Get()
	if err := applyHostOverrides(&cfg, input.Host); err != nil {
		return err
	}
	scheme, automatic, err := input.ResolveScheme(cfg.DefaultScheme)
	if err != nil {
		return err
	}
	original, err := httpraw.Parse(variants[0].RawHTTP, scheme)
	if err != nil {
		return fmt.Errorf("爆破模板展开后的 HTTP 报文无效: %w", err)
	}
	if len(cfg.AllowedHosts) == 0 {
		cfg.AllowedHosts = []string{original.Host()}
	}
	cfg.MaxConcurrency = concurrency
	cfg.RequestsPerSecond = max(cfg.RequestsPerSecond, float64(concurrency)*10)
	certificate, err := clientcert.FromScanInput(input)
	if err != nil {
		return err
	}
	client, err := transport.NewWithGovernorAndCertificate(cfg, transport.Hooks{}, m.governor, certificate)
	if err != nil {
		return err
	}
	defer client.Close()

	usedScheme := scheme
	if automatic {
		usedScheme, err = m.replayAutoScheme(ctx, client, variants[0], cfg.TimeoutSeconds, onResult)
		if err != nil {
			return err
		}
		variants = variants[1:]
	}
	if len(variants) == 0 {
		return nil
	}
	jobs := make(chan ReplayVariant)
	var wait sync.WaitGroup
	workerCount := min(concurrency, len(variants))
	wait.Add(workerCount)
	for range workerCount {
		go func() {
			defer wait.Done()
			for variant := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				request, parseErr := httpraw.Parse(variant.RawHTTP, usedScheme)
				if parseErr != nil {
					onResult(ReplayResult{Index: variant.Index, Payload: variant.Payload, Scheme: usedScheme, Error: parseErr.Error()})
					continue
				}
				request = request.WithScheme(usedScheme)
				started := time.Now()
				response, sendErr := client.Send(ctx, request)
				result := replayResultFromResponse(variant, response, request.Scheme, time.Since(started), sendErr)
				onResult(result)
			}
		}()
	}
	for _, variant := range variants {
		select {
		case jobs <- variant:
		case <-ctx.Done():
			close(jobs)
			wait.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	wait.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) replayAutoScheme(
	ctx context.Context,
	client *transport.Client,
	variant ReplayVariant,
	timeoutSeconds int,
	onResult func(ReplayResult),
) (string, error) {
	request, err := httpraw.Parse(variant.RawHTTP, "http")
	if err != nil {
		return "", fmt.Errorf("爆破模板展开后的 HTTP 报文无效: %w", err)
	}
	started := time.Now()
	response, used, _, sendErr := client.SendWithSchemeFallback(ctx, request, true)
	result := replayResultFromResponse(variant, response, used.Scheme, time.Since(started), sendErr)
	onResult(result)
	if sendErr != nil {
		return "", fmt.Errorf("爆破首个请求连通性检测失败: %s", transport.FriendlyError(sendErr, timeoutSeconds))
	}
	return used.Scheme, nil
}

func replayResultFromResponse(variant ReplayVariant, response model.Response, scheme string, elapsed time.Duration, err error) ReplayResult {
	result := ReplayResult{
		Index: variant.Index, Payload: variant.Payload, Scheme: scheme,
		StatusCode: response.StatusCode, ResponseBytes: response.RawBytes,
		CapturedBytes: len(response.Body), ElapsedMS: elapsed.Milliseconds(),
		ResponseTruncated: response.Truncated,
	}
	if result.ResponseBytes == 0 {
		result.ResponseBytes = int64(len(response.Body))
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.RawResponse = rawReplayResponse(response)
	return result
}

func rawReplayResponse(response model.Response) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "HTTP/1.1 %d %s\r\n", response.StatusCode, http.StatusText(response.StatusCode))
	names := make([]string, 0, len(response.HeaderValues))
	for name := range response.HeaderValues {
		names = append(names, name)
	}
	if len(names) == 0 {
		for name := range response.Headers {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		values := response.HeaderValues[name]
		if len(values) == 0 {
			values = []string{response.Headers[name]}
		}
		for _, value := range values {
			if value != "" {
				fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
			}
		}
	}
	builder.WriteString("\r\n")
	builder.Write(response.Body)
	return builder.String()
}

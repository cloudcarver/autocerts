package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/cloudcarver/autocerts/internal/app"
	"github.com/cloudcarver/autocerts/internal/config"
	"github.com/cloudcarver/autocerts/internal/fcinvoke"
	"github.com/cloudcarver/autocerts/internal/renewal"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	command, tail := detectCommand(args)
	if command == "" {
		printUsage(stderr)
		return fmt.Errorf("command is required")
	}

	switch command {
	case "issue":
		return runIssueCommand(tail, stdout, stderr)
	case "reconcile":
		return runReconcileCommand(tail, stdout, stderr)
	case "ls-regions":
		return runListRegionsCommand(tail, stdout, stderr)
	case "modify-regions":
		return runModifyRegionsCommand(tail, stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unsupported command %q", command)
	}
}

func detectCommand(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}

type invokeOptions struct {
	aliyunBin      string
	fcRegion       string
	functionName   string
	qualifier      string
	readTimeout    int
	connectTimeout int
}

func newInvokeFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *invokeOptions) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := &invokeOptions{}
	fs.StringVar(&opts.aliyunBin, "aliyun-bin", "aliyun", "aliyun CLI binary")
	fs.StringVar(&opts.fcRegion, "fc-region", "cn-shenzhen", "function compute region")
	fs.StringVar(&opts.functionName, "function", "autocerts", "function compute function name")
	fs.StringVar(&opts.qualifier, "qualifier", "", "function qualifier")
	fs.IntVar(&opts.readTimeout, "read-timeout", 600, "aliyun CLI read timeout in seconds")
	fs.IntVar(&opts.connectTimeout, "connect-timeout", 30, "aliyun CLI connect timeout in seconds")
	return fs, opts
}

type functionConfigOptions struct {
	aliyunBin      string
	fcRegion       string
	functionName   string
	readTimeout    int
	connectTimeout int
}

func newFunctionConfigFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *functionConfigOptions) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := &functionConfigOptions{}
	fs.StringVar(&opts.aliyunBin, "aliyun-bin", "aliyun", "aliyun CLI binary")
	fs.StringVar(&opts.fcRegion, "fc-region", "cn-shenzhen", "function compute region")
	fs.StringVar(&opts.functionName, "function", "autocerts", "function compute function name")
	fs.IntVar(&opts.readTimeout, "read-timeout", 600, "aliyun CLI read timeout in seconds")
	fs.IntVar(&opts.connectTimeout, "connect-timeout", 30, "aliyun CLI connect timeout in seconds")
	return fs, opts
}

func runIssueCommand(args []string, stdout, stderr io.Writer) error {
	fs, invokeOpts := newInvokeFlagSet("issue", stderr)

	var (
		domainsCSV      string
		dnsProviderRaw  string
		certificateName string
		dryRun          bool
		async           bool
		jsonOutput      bool
	)
	fs.StringVar(&domainsCSV, "domains", "", "comma-separated certificate domains")
	fs.StringVar(&dnsProviderRaw, "dns-provider", "", "dns provider: cloudflare or aliyun")
	fs.StringVar(&certificateName, "certificate-name", "", "optional certificate name")
	fs.BoolVar(&dryRun, "dry-run", false, "invoke issue in dry-run mode")
	fs.BoolVar(&async, "async", false, "invoke function asynchronously")
	fs.BoolVar(&jsonOutput, "json", false, "print raw JSON response")

	if err := fs.Parse(args); err != nil {
		return err
	}

	dnsProvider, err := config.ParseDNSProvider(dnsProviderRaw)
	if err != nil {
		return err
	}

	cliArgs, err := fcinvoke.BuildIssueInvokeArgs(fcinvoke.IssueOptions{
		FunctionRegion:  invokeOpts.fcRegion,
		FunctionName:    invokeOpts.functionName,
		Qualifier:       invokeOpts.qualifier,
		Domains:         fcinvoke.SplitCSV(domainsCSV),
		DNSProvider:     dnsProvider,
		CertificateName: certificateName,
		DryRun:          dryRun,
		Async:           async,
	})
	if err != nil {
		return err
	}

	output, err := runAliyunCLI(invokeOpts.aliyunBin, invokeOpts.readTimeout, invokeOpts.connectTimeout, cliArgs)
	if err != nil {
		if !async && strings.Contains(err.Error(), "context deadline exceeded") {
			return fmt.Errorf("invoke fc issue via aliyun cli: %w; issue 是长耗时操作，建议改用 --async，或先把 FC timeout 调大到至少 600 秒", err)
		}
		return fmt.Errorf("invoke fc issue via aliyun cli: %w", err)
	}

	return renderCLIResponse(stdout, output, jsonOutput, async, invokeOpts.fcRegion, invokeOpts.functionName)
}

func runReconcileCommand(args []string, stdout, stderr io.Writer) error {
	fs, invokeOpts := newInvokeFlagSet("reconcile", stderr)

	var (
		dryRun     bool
		async      bool
		jsonOutput bool
	)
	fs.BoolVar(&dryRun, "dry-run", false, "invoke reconcile in dry-run mode")
	fs.BoolVar(&async, "async", false, "invoke function asynchronously")
	fs.BoolVar(&jsonOutput, "json", false, "print raw JSON response")

	if err := fs.Parse(args); err != nil {
		return err
	}

	body, err := json.Marshal(map[string]any{
		"mode":   config.ModeReconcile,
		"dryRun": dryRun,
	})
	if err != nil {
		return fmt.Errorf("marshal reconcile payload: %w", err)
	}

	cliArgs := buildInvokeFunctionArgs(invokeCall{
		FunctionRegion: invokeOpts.fcRegion,
		FunctionName:   invokeOpts.functionName,
		Qualifier:      invokeOpts.qualifier,
		Body:           body,
		Async:          async,
	})

	output, err := runAliyunCLI(invokeOpts.aliyunBin, invokeOpts.readTimeout, invokeOpts.connectTimeout, cliArgs)
	if err != nil {
		if !async && strings.Contains(err.Error(), "context deadline exceeded") {
			return fmt.Errorf("invoke fc reconcile via aliyun cli: %w; reconcile 可能是长耗时操作，建议改用 --async，或先把 FC timeout 调大", err)
		}
		return fmt.Errorf("invoke fc reconcile via aliyun cli: %w", err)
	}

	return renderCLIResponse(stdout, output, jsonOutput, async, invokeOpts.fcRegion, invokeOpts.functionName)
}

func runListRegionsCommand(args []string, stdout, stderr io.Writer) error {
	fs, cfgOpts := newFunctionConfigFlagSet("ls-regions", stderr)
	var jsonOutput bool
	fs.BoolVar(&jsonOutput, "json", false, "print raw JSON response")

	if err := fs.Parse(args); err != nil {
		return err
	}

	functionConfig, err := getFunctionConfig(*cfgOpts)
	if err != nil {
		return err
	}

	if jsonOutput {
		return writeJSON(stdout, regionsView{
			FunctionRegion: cfgOpts.fcRegion,
			FunctionName:   cfgOpts.functionName,
			Raw:            strings.TrimSpace(functionConfig.EnvironmentVariables["REGIONS"]),
			Regions:        fcinvoke.SplitCSV(functionConfig.EnvironmentVariables["REGIONS"]),
		})
	}

	_, err = io.WriteString(stdout, formatRegionsView(cfgOpts.fcRegion, cfgOpts.functionName, functionConfig.EnvironmentVariables["REGIONS"]))
	return err
}

func runModifyRegionsCommand(args []string, stdout, stderr io.Writer) error {
	fs, cfgOpts := newFunctionConfigFlagSet("modify-regions", stderr)
	var (
		regionsCSV string
		jsonOutput bool
		dryRun     bool
	)
	fs.StringVar(&regionsCSV, "regions", "", "comma-separated region list")
	fs.BoolVar(&jsonOutput, "json", false, "print raw JSON response")
	fs.BoolVar(&dryRun, "dry-run", false, "show the change without updating the function")

	if err := fs.Parse(args); err != nil {
		return err
	}

	regions := fcinvoke.SplitCSV(regionsCSV)
	if len(regions) == 0 {
		return fmt.Errorf("regions are required")
	}

	functionConfig, err := getFunctionConfig(*cfgOpts)
	if err != nil {
		return err
	}

	previousRaw := strings.TrimSpace(functionConfig.EnvironmentVariables["REGIONS"])
	updatedEnvs := cloneEnvs(functionConfig.EnvironmentVariables)
	updatedEnvs["REGIONS"] = strings.Join(regions, ",")

	view := regionsMutationView{
		FunctionRegion: cfgOpts.fcRegion,
		FunctionName:   cfgOpts.functionName,
		PreviousRaw:    previousRaw,
		Previous:       fcinvoke.SplitCSV(previousRaw),
		Raw:            updatedEnvs["REGIONS"],
		Regions:        regions,
		DryRun:         dryRun,
	}

	if !dryRun {
		if err := updateFunctionEnvs(*cfgOpts, updatedEnvs); err != nil {
			return err
		}
	}

	if jsonOutput {
		return writeJSON(stdout, view)
	}

	_, err = io.WriteString(stdout, formatRegionsMutationView(view))
	return err
}

type invokeCall struct {
	FunctionRegion string
	FunctionName   string
	Qualifier      string
	Body           []byte
	Async          bool
}

func buildInvokeFunctionArgs(call invokeCall) []string {
	args := []string{
		"--region", strings.TrimSpace(call.FunctionRegion),
		"fc", "InvokeFunction",
		"--functionName", strings.TrimSpace(call.FunctionName),
		"--body", string(call.Body),
	}
	if call.Async {
		args = append(args, "--header", "x-fc-invocation-type=Async")
	}
	if strings.TrimSpace(call.Qualifier) != "" {
		args = append(args, "--qualifier", strings.TrimSpace(call.Qualifier))
	}
	return args
}

func runAliyunCLI(aliyunBin string, readTimeout, connectTimeout int, cliArgs []string) ([]byte, error) {
	baseArgs := []string{
		"--read-timeout", fmt.Sprintf("%d", readTimeout),
		"--connect-timeout", fmt.Sprintf("%d", connectTimeout),
	}
	baseArgs = append(baseArgs, cliArgs...)

	cmd := exec.Command(aliyunBin, baseArgs...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

type fcFunctionConfig struct {
	EnvironmentVariables map[string]string `json:"environmentVariables"`
}

func getFunctionConfig(opts functionConfigOptions) (*fcFunctionConfig, error) {
	output, err := runAliyunCLI(opts.aliyunBin, opts.readTimeout, opts.connectTimeout, []string{
		"--region", opts.fcRegion,
		"fc", "GetFunction",
		"--functionName", opts.functionName,
	})
	if err != nil {
		return nil, fmt.Errorf("get function config via aliyun cli: %w", err)
	}

	var result fcFunctionConfig
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parse function config: %w", err)
	}
	if result.EnvironmentVariables == nil {
		result.EnvironmentVariables = map[string]string{}
	}
	return &result, nil
}

func updateFunctionEnvs(opts functionConfigOptions, envs map[string]string) error {
	body, err := json.Marshal(map[string]any{
		"environmentVariables": envs,
	})
	if err != nil {
		return fmt.Errorf("marshal function update body: %w", err)
	}

	_, err = runAliyunCLI(opts.aliyunBin, opts.readTimeout, opts.connectTimeout, []string{
		"--region", opts.fcRegion,
		"fc", "PUT", fmt.Sprintf("/2023-03-30/functions/%s", opts.functionName),
		"--body", string(body),
	})
	if err != nil {
		return fmt.Errorf("update function envs via aliyun cli: %w", err)
	}
	return nil
}

func cloneEnvs(envs map[string]string) map[string]string {
	out := make(map[string]string, len(envs))
	for key, value := range envs {
		out[key] = value
	}
	return out
}

type regionsView struct {
	FunctionRegion string   `json:"functionRegion"`
	FunctionName   string   `json:"functionName"`
	Raw            string   `json:"raw"`
	Regions        []string `json:"regions"`
}

type regionsMutationView struct {
	FunctionRegion string   `json:"functionRegion"`
	FunctionName   string   `json:"functionName"`
	PreviousRaw    string   `json:"previousRaw"`
	Previous       []string `json:"previousRegions,omitempty"`
	Raw            string   `json:"raw"`
	Regions        []string `json:"regions"`
	DryRun         bool     `json:"dryRun,omitempty"`
}

func formatRegionsView(fcRegion, functionName, raw string) string {
	regions := fcinvoke.SplitCSV(raw)
	lines := []string{
		fmt.Sprintf("函数: %s/%s", fcRegion, functionName),
	}
	if len(regions) == 0 {
		lines = append(lines, "REGIONS: <empty>")
		return strings.Join(lines, "\n") + "\n"
	}

	lines = append(lines, fmt.Sprintf("REGIONS: %s", strings.Join(regions, ",")))
	lines = append(lines, fmt.Sprintf("地域数: %d", len(regions)))
	lines = append(lines, fmt.Sprintf("列表: %s", strings.Join(regions, ", ")))
	return strings.Join(lines, "\n") + "\n"
}

func formatRegionsMutationView(view regionsMutationView) string {
	status := "已更新 REGIONS"
	if view.DryRun {
		status = "dry-run，未真正更新 REGIONS"
	}

	lines := []string{
		status,
		fmt.Sprintf("函数: %s/%s", view.FunctionRegion, view.FunctionName),
		fmt.Sprintf("旧值: %s", emptyValue(view.PreviousRaw)),
		fmt.Sprintf("新值: %s", emptyValue(view.Raw)),
		fmt.Sprintf("列表: %s", strings.Join(view.Regions, ", ")),
	}
	return strings.Join(lines, "\n") + "\n"
}

func emptyValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "<empty>"
	}
	return value
}

func writeJSON(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		data = append(data, '\n')
	}
	_, err = w.Write(data)
	return err
}

func renderCLIResponse(w io.Writer, raw []byte, jsonOutput, async bool, fcRegion, functionName string) error {
	payload := normalizeCLIResponse(raw)
	if len(payload) == 0 {
		if async {
			_, err := fmt.Fprintf(w, "已提交异步调用到 %s/%s\n", fcRegion, functionName)
			return err
		}
		return nil
	}

	if jsonOutput {
		if !bytes.HasSuffix(payload, []byte("\n")) {
			payload = append(payload, '\n')
		}
		_, err := w.Write(payload)
		return err
	}

	formatted, err := formatHumanResponse(payload)
	if err != nil {
		if !bytes.HasSuffix(payload, []byte("\n")) {
			payload = append(payload, '\n')
		}
		_, writeErr := w.Write(payload)
		if writeErr != nil {
			return writeErr
		}
		return nil
	}

	_, err = io.WriteString(w, formatted)
	return err
}

func normalizeCLIResponse(raw []byte) []byte {
	payload := bytes.TrimSpace(raw)
	if len(payload) == 0 {
		return nil
	}

	var quoted string
	if err := json.Unmarshal(payload, &quoted); err == nil {
		return bytes.TrimSpace([]byte(quoted))
	}
	return payload
}

func formatHumanResponse(payload []byte) (string, error) {
	var response app.Response
	if err := json.Unmarshal(payload, &response); err != nil {
		return "", err
	}

	switch response.Mode {
	case config.ModeIssue:
		return formatIssueResponse(response.Issue), nil
	case config.ModeReconcile:
		return formatReconcileResponse(response.Reconcile), nil
	case config.ModeSmoke:
		return formatSmokeResponse(response.Smoke), nil
	default:
		return string(payload) + "\n", nil
	}
}

func formatIssueResponse(result *app.IssueResult) string {
	if result == nil {
		return "issue 已完成，但返回为空\n"
	}

	status := "已签发并上传新证书"
	if result.DryRun {
		status = "dry-run，未真正签发"
	} else if result.Reused {
		status = "已复用现有证书"
	}

	lines := []string{
		status,
		fmt.Sprintf("域名: %s", strings.Join(result.Domains, ", ")),
		fmt.Sprintf("DNS Provider: %s", result.DNSProvider),
		fmt.Sprintf("证书名: %s", result.CertificateName),
	}
	if len(result.Uploads) > 0 {
		upload := result.Uploads[0]
		lines = append(lines, fmt.Sprintf("CAS: %s (ID %d)", upload.CertIdentifier, upload.CertificateID))
	}
	if !result.ExpiresAt.IsZero() {
		lines = append(lines, fmt.Sprintf("过期时间: %s", result.ExpiresAt.Format(time.RFC3339)))
	}
	return strings.Join(lines, "\n") + "\n"
}

func formatReconcileResponse(result *renewal.Result) string {
	if result == nil {
		return "reconcile 已完成，但返回为空\n"
	}

	lines := []string{
		"reconcile 已完成",
		fmt.Sprintf("发现: %d", result.Discovered),
		fmt.Sprintf("即将过期: %d", result.Expiring),
		fmt.Sprintf("已重签: %d", result.Renewed),
		fmt.Sprintf("已更新引用: %d", result.Updated),
	}
	if result.DryRun {
		lines = append(lines, "模式: dry-run")
	}
	if len(result.Actions) > 0 {
		lines = append(lines, fmt.Sprintf("动作数: %d", len(result.Actions)))
	}
	if len(result.Warnings) > 0 {
		lines = append(lines, fmt.Sprintf("告警: %d", len(result.Warnings)))
		for _, warning := range result.Warnings {
			lines = append(lines, fmt.Sprintf("warning: %s", warning))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func formatSmokeResponse(result *app.SmokeResult) string {
	if result == nil {
		return "smoke 已完成，但返回为空\n"
	}

	lines := []string{"smoke 已完成"}
	for _, check := range result.Checks {
		status := "OK"
		if !check.OK {
			status = "FAIL"
		}
		line := fmt.Sprintf("%s: %s", check.Name, status)
		if check.Message != "" {
			line = fmt.Sprintf("%s (%s)", line, check.Message)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n"
}

func printUsage(w io.Writer) {
	commands := []string{
		"issue          申请或复用证书",
		"reconcile      触发自动续期扫描",
		"ls-regions     查看线上函数的 REGIONS 环境变量",
		"modify-regions 更新线上函数的 REGIONS 环境变量",
	}
	sort.Strings(commands)

	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  autocerts issue --domains example.com --dns-provider cloudflare")
	_, _ = fmt.Fprintln(w, "  autocerts reconcile [--dry-run] [--async]")
	_, _ = fmt.Fprintln(w, "  autocerts ls-regions")
	_, _ = fmt.Fprintln(w, "  autocerts modify-regions --regions cn-hangzhou,cn-beijing")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Commands:")
	for _, line := range commands {
		_, _ = fmt.Fprintln(w, "  "+line)
	}
}

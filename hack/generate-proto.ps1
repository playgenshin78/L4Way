$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$cache = Join-Path $root '.cache\tools'
$archive = Join-Path $cache 'protoc-35.0-win64.zip'
$protocHome = Join-Path $cache 'protoc-35.0'
$protoc = Join-Path $protocHome 'bin\protoc.exe'
$bin = Join-Path $cache 'bin'

New-Item -ItemType Directory -Force -Path $cache, $bin | Out-Null

if (-not (Test-Path -LiteralPath $protoc)) {
    if (-not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest `
            -Uri 'https://github.com/protocolbuffers/protobuf/releases/download/v35.0/protoc-35.0-win64.zip' `
            -OutFile $archive
    }
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = 'd1cede9e308cc3eb072392af1c02ccae4bdd3d2f374ec2970dbd8cdfdaa91363'
    if ($actual -ne $expected) {
        throw "protoc archive checksum mismatch: expected=$expected actual=$actual"
    }
    if (Test-Path -LiteralPath $protocHome) {
		$resolvedRoot = [System.IO.Path]::GetFullPath($root)
		$resolvedTarget = [System.IO.Path]::GetFullPath($protocHome)
		if (-not $resolvedTarget.StartsWith((Join-Path $resolvedRoot '.cache\tools\protoc-35.0'), [System.StringComparison]::OrdinalIgnoreCase)) {
			throw "refusing to replace protoc directory outside the workspace cache: $resolvedTarget"
		}
        Remove-Item -LiteralPath $protocHome -Recurse -Force
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $protocHome
}

$env:GOBIN = $bin
$env:GOCACHE = Join-Path $root '.cache\go-build'
$env:GOMODCACHE = Join-Path $root '.cache\gomod'
$env:GOTMPDIR = Join-Path $root '.cache\tmp'
New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOMODCACHE, $env:GOTMPDIR | Out-Null

$protoRoot = Join-Path $root 'proto'
$goPlugin = Join-Path $bin 'protoc-gen-go.exe'
$grpcPlugin = Join-Path $bin 'protoc-gen-go-grpc.exe'

$goPluginVersion = if (Test-Path -LiteralPath $goPlugin) { & $goPlugin --version } else { '' }
if ($goPluginVersion -ne 'protoc-gen-go.exe v1.36.11') {
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
    if ($LASTEXITCODE -ne 0) {
        throw "install protoc-gen-go failed with exit code $LASTEXITCODE"
    }
}

$grpcPluginVersion = if (Test-Path -LiteralPath $grpcPlugin) { & $grpcPlugin --version } else { '' }
if ($grpcPluginVersion -ne 'protoc-gen-go-grpc 1.6.2') {
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
    if ($LASTEXITCODE -ne 0) {
        throw "install protoc-gen-go-grpc failed with exit code $LASTEXITCODE"
    }
}

& $protoc `
    "--proto_path=$protoRoot" `
    "--plugin=protoc-gen-go=$goPlugin" `
    "--plugin=protoc-gen-go-grpc=$grpcPlugin" `
    "--go_out=$root" `
    '--go_opt=module=flux.local/flux' `
    "--go-grpc_out=$root" `
    '--go-grpc_opt=module=flux.local/flux' `
    (Join-Path $protoRoot 'flux\control\v1\control.proto')
if ($LASTEXITCODE -ne 0) {
    throw "protoc failed with exit code $LASTEXITCODE"
}

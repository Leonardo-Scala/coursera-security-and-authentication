#!/usr/bin/env pwsh

# SafeVault Security Test Runner
# This script runs comprehensive security tests for SQL injection and XSS vulnerabilities

Write-Host "SafeVault Security Testing Suite" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green
Write-Host ""

# Change to the project directory
$projectPath = "8 - Security and Authentication\Modulo 4\SafeVault"
if (Test-Path $projectPath) {
    Set-Location $projectPath
    Write-Host "? Changed to project directory: $projectPath" -ForegroundColor Green
} else {
    Write-Host "? Project directory not found: $projectPath" -ForegroundColor Red
    exit 1
}

# Restore packages
Write-Host ""
Write-Host "Restoring NuGet packages..." -ForegroundColor Yellow
dotnet restore
if ($LASTEXITCODE -ne 0) {
    Write-Host "? Failed to restore packages" -ForegroundColor Red
    exit 1
}
Write-Host "? Packages restored successfully" -ForegroundColor Green

# Build the project
Write-Host ""
Write-Host "Building project..." -ForegroundColor Yellow
dotnet build --no-restore
if ($LASTEXITCODE -ne 0) {
    Write-Host "? Build failed" -ForegroundColor Red
    exit 1
}
Write-Host "? Build successful" -ForegroundColor Green

# Run security tests
Write-Host ""
Write-Host "Running Security Tests..." -ForegroundColor Yellow
Write-Host ""

# Run specific test categories
$testCategories = @(
    @{Name="Input Validation Tests"; Filter="TestInputValidation"},
    @{Name="Advanced Security Tests"; Filter="AdvancedSecurityTests"},
    @{Name="Integration Tests"; Filter="SecurityIntegrationTests"}
)

$totalPassed = 0
$totalFailed = 0

foreach ($category in $testCategories) {
    Write-Host "Running $($category.Name)..." -ForegroundColor Cyan
    Write-Host ("-" * 50) -ForegroundColor Gray
    
    $result = dotnet test --no-build --filter "ClassName~$($category.Filter)" --logger "console;verbosity=detailed" 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "? $($category.Name) - ALL TESTS PASSED" -ForegroundColor Green
        # Try to extract test count from output
        $passedTests = ($result | Select-String "Passed:.*?(\d+)" | ForEach-Object { $_.Matches[0].Groups[1].Value })
        if ($passedTests) {
            $totalPassed += [int]$passedTests
        }
    } else {
        Write-Host "? $($category.Name) - SOME TESTS FAILED" -ForegroundColor Red
        $failedTests = ($result | Select-String "Failed:.*?(\d+)" | ForEach-Object { $_.Matches[0].Groups[1].Value })
        if ($failedTests) {
            $totalFailed += [int]$failedTests
        }
    }
    Write-Host ""
}

# Generate summary report
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Green
Write-Host "SECURITY TEST SUMMARY REPORT" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Green
Write-Host "Test Run Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""

if ($totalFailed -eq 0) {
    Write-Host "?? ALL SECURITY TESTS PASSED!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your SafeVault application demonstrates:" -ForegroundColor Green
    Write-Host "? Strong SQL Injection Protection" -ForegroundColor Green
    Write-Host "? Robust XSS Prevention" -ForegroundColor Green
    Write-Host "? Comprehensive Input Validation" -ForegroundColor Green
    Write-Host "? Proper Unicode Normalization" -ForegroundColor Green
    Write-Host "? Efficient Performance Under Attack" -ForegroundColor Green
} else {
    Write-Host "?? SECURITY ISSUES DETECTED!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Tests Passed: $totalPassed" -ForegroundColor Green
    Write-Host "Tests Failed: $totalFailed" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please review failed tests and address security vulnerabilities." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Test Categories Executed:" -ForegroundColor White
Write-Host "• SQL Injection Tests (Basic & Advanced)" -ForegroundColor Gray
Write-Host "• Cross-Site Scripting (XSS) Tests" -ForegroundColor Gray
Write-Host "• Unicode and Encoding Attacks" -ForegroundColor Gray
Write-Host "• Mixed Attack Vectors" -ForegroundColor Gray
Write-Host "• Performance Under Load" -ForegroundColor Gray
Write-Host "• Integration Tests" -ForegroundColor Gray

Write-Host ""
Write-Host "For detailed results, check the test output above." -ForegroundColor Gray
Write-Host "=" * 80 -ForegroundColor Green

# Return to original directory
Set-Location -
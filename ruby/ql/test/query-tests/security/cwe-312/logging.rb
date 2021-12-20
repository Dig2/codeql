stdout_logger = Logger.new STDOUT

password = "043697b96909e03ca907599d6420555f"

# BAD: password logged as plaintext
stdout_logger.debug password
# BAD: password logged as plaintext
stdout_logger.error password
# BAD: password logged as plaintext
stdout_logger.fatal password
# BAD: password logged as plaintext
stdout_logger.info password
# BAD: password logged as plaintext
stdout_logger.unknown password
# BAD: password logged as plaintext
stdout_logger.warn password

# BAD: password logged as plaintext
stdout_logger.add Logger::WARN, password
# BAD: password logged as plaintext
stdout_logger.add Logger::WARN, "message", password
# BAD: password logged as plaintext
stdout_logger.log Logger::WARN, password

# BAD: password logged as plaintext
stdout_logger << "pw: #{password}"
# BAD: sensitive data in the progname will taint subsequent logging calls
stdout_logger.progname = password

hsh1 = { password: "aec5058e61f7f122998b1a30ee2c66b6" }
hsh2 = {}
hsh2[:password] = "beeda625d7306b45784d91ea0336e201"

# BAD: password logged as plaintext
stdout_logger.info hsh1[:password]
# BAD: password logged as plaintext
stdout_logger.info hsh2[:password]

password_masked_sub = "ca497451f5e883662fb1a37bc9ec7838"
password_masked_gsub = "a7e3747b19930d4f4b8181047194832f"
password_masked_sub.sub!(/.+/, "[password]")
password_masked_gsub.gsub!(/./, "*")

# GOOD: password is effectively masked before logging
stdout_logger.info password_masked_sub
# GOOD: password is effectively masked before logging
stdout_logger.info password_masked_gsub

password_masked_ineffective_sub = "ca497451f5e883662fb1a37bc9ec7838"
password_masked_ineffective_gsub = "a7e3747b19930d4f4b8181047194832f"
password_masked_ineffective_sub.sub!(/./, "[password]")
password_masked_ineffective_gsub.gsub!(/[A-Z]/, "*")

# BAD: password masked ineffectively
stdout_logger.info password_masked_ineffective_sub
# BAD: password masked ineffectively
stdout_logger.info password_masked_ineffective_gsub

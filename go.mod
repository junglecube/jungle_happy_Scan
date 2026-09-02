module jungle_happy_Scan

go 1.26

require (
	golang.org/x/text v0.0.0
	software.sslmate.com/src/go-pkcs12 v0.7.0
)

replace golang.org/x/text => ./third_party/golang.org/x/text

replace software.sslmate.com/src/go-pkcs12 => ./third_party/software.sslmate.com/src/go-pkcs12

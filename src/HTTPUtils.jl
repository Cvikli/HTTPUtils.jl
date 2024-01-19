module HTTPUtils

using HTTP
using Dates
using JSON3
using SHA

export GET, POST, DELETE

timestamp() = Int64(floor(Dates.datetime2unix(Dates.now(Dates.UTC))))

# Keyed-hash Message authentication Code
# see e.g. definition & calculation details from wikipedia
hmac(key::Vector{UInt8}, msg::Vector{UInt8}, hash, blocksize::Int=64) = begin
  length(key) > blocksize && (key = hash(key))

	pad = blocksize - length(key)

	if pad > 0
		resize!(key, blocksize)
		key[end - pad + 1:end] = 0
	end

	o_key_pad = key .⊻ 0x5c
	i_key_pad = key .⊻ 0x36

	hash([o_key_pad; hash([i_key_pad; msg])])
end

# provide digital signature
do_sign(queryString, apiSecret) = bytes2hex(hmac(Vector{UInt8}(apiSecret), Vector{UInt8}(queryString), SHA.sha256))

# parse HTTP response to JSON
# dangerous??, it can be run only once, because JSON.parse modify the data... or IDK...
r2j(response)   = JSON3.read(String(response.body))
s2j(stream_res) = JSON3.read(String(stream_res))

REQUEST(method, url::String) = r2j(method(url))
REQUEST(method, uri::String, body::String; header=nothing, secret=nothing, body_as_querystring=false, verbose=false) = begin
	secret !== nothing && (body = body * "&signature=" * do_sign(body, secret))

	verbose && println(method, ": ", uri, body, " ", header)

 	if header !== nothing
		if body_as_querystring
			return r2j(method(uri * "?" * body, header))
		else
			return r2j(method(uri, header, body))
		end
	else
		return r2j(method(uri * "?" * body))
	end
end

GET(url::String)    = REQUEST(HTTP.get, url)
GET(uri::String,    body::String; header=nothing, secret=nothing, body_as_querystring=false, verbose=false) = REQUEST(HTTP.get,    uri, body, header=header, secret=secret, body_as_querystring=body_as_querystring, verbose=verbose)
POST(url::String)   = REQUEST(HTTP.post, url)
POST(uri::String,   body::String; header=nothing, secret=nothing, body_as_querystring=false, verbose=false) = REQUEST(HTTP.post,   uri, body, header=header, secret=secret, body_as_querystring=body_as_querystring, verbose=verbose)
DELETE(url::String) = REQUEST(HTTP.delete, url)
DELETE(uri::String, body::String; header=nothing, secret=nothing, body_as_querystring=false, verbose=false) = REQUEST(HTTP.delete, uri, body, header=header, secret=secret, body_as_querystring=body_as_querystring, verbose=verbose)

WEBSOCKETFN(url::String; verbose=false) = HTTP.WebSockets.open(url, verbose)  # @async can't see this function
WEBSOCKET = HTTP.WebSockets



end # module HTTPUtils

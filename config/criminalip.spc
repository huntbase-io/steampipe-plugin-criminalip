connection "criminalip" {
  plugin = "huntbase-io/criminalip"

  # Your Criminal IP API key. Get one from https://www.criminalip.io/mypage/information
  # If not set here, the CRIMINALIP_API_KEY environment variable is used.
  # api_key = "YOUR_CRIMINALIP_API_KEY"

  # Maximum number of records a search table (banner, asset, exploit, domain
  # reports) fetches per query. A SQL LIMIT can lower this but never raise it.
  # Every page of results costs API credits, so this defaults to 100. The API
  # never returns more than 10,000 records per query.
  # max_search_results = 100

  # Override the API endpoint (for proxies or testing).
  # base_url = "https://api.criminalip.io"
}

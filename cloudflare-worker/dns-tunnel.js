// DNS Bypass v3.0 - Stealth Tunnel Worker
// Deploy to: Cloudflare Workers (Free tier: 100,000 requests/day)

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // CORS headers for cross-origin requests
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  }

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  // Only accept POST requests
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { 
      status: 405,
      headers: corsHeaders 
    })
  }

  try {
    // Parse request body
    const body = await request.json()
    const { domain, type = 'A' } = body

    if (!domain) {
      return new Response(JSON.stringify({ error: 'Domain required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // Perform DNS-over-HTTPS query to Cloudflare
    const dohUrl = `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`
    const dohResponse = await fetch(dohUrl, {
      headers: {
        'Accept': 'application/dns-json'
      }
    })

    const dnsData = await dohResponse.json()

    // Extract IPs
    const ips = dnsData.Answer 
      ? dnsData.Answer
          .filter(a => a.type === 1 || a.type === 28) // A or AAAA
          .map(a => a.data)
      : []

    // Return obfuscated response
    const response = {
      success: true,
      domain: domain,
      ips: ips,
      ttl: dnsData.Answer?.[0]?.TTL || 300,
      timestamp: Date.now()
    }

    return new Response(JSON.stringify(response), {
      status: 200,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300'
      }
    })

  } catch (error) {
    return new Response(JSON.stringify({ 
      error: 'DNS query failed',
      message: error.message 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
  }
}

import time
from collections import defaultdict
from django.http import JsonResponse


class SimpleRateLimitMiddleware:
    window_seconds = 60
    max_requests = 60

    def __init__(self, get_response):
        self.get_response = get_response
        self.buckets = defaultdict(list)

    def __call__(self, request):
        if request.path == '/api/integrations/wazuh/alerts' and request.method == 'POST':
            ip = request.META.get('REMOTE_ADDR', 'unknown')
            now = time.time()
            bucket = [timestamp for timestamp in self.buckets[ip] if now - timestamp < self.window_seconds]
            bucket.append(now)
            self.buckets[ip] = bucket
            if len(bucket) > self.max_requests:
                return JsonResponse({'detail': 'rate limit exceeded'}, status=429)
        return self.get_response(request)

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from swift.common.swob import Response, Request

from swift.common.utils import split_path, cache_from_env, get_logger
from swift.common.memcached import MemcacheConnectionError


class ObjectRateLimitMiddleware(object):
    """
    Object Rate limiting middleware

    Rate limits object requests:
    Starts a counter, which allows up to <amount> requests.
    If you try to do more, you get an http 498 'rate limit reached'
    Every TTL, the counter expires and starts from 0 on the next request.
    You can configure multiple limitations and specify a string
    which must be contained within the path (including querystring) for
    the setting to apply. For every req, tries to match the patterns in order,
    (NOTE: python will probably return in diff. order!)
    and falls back to the match-less version, if specified
    Configuration examples:
    # 10 reqs, TTL 3600s
    object_ratelimit = 10:3600
    # same, but only for req paths with the phrase 'temp_url_sig' in them
    object_ratelimit_temp_url_sig = 10:3600

    You can also exempt connections from the object rate limiting based on a header.
    like so:
    object_ratelimit-exempt_header_x_forwarded_for = None:<ip>[:<ip>[:(...)
    This will exempt all connections that have one of the allowed values for x_forwarded_for.
    (note that this particular header may not always be reliable)
    The value 'None' means "header not set".
    """

    def __init__(self, app, conf, logger=None):
        self.app = app
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='objectratelimit')
        self.logger.set_statsd_prefix('objectratelimit')
        self.memcache_client = None
        self.conf_limits = []
        self.exempt_header = {}
        for conf_key in conf.keys():
            if conf_key.startswith('object_ratelimit_'):
                match = conf_key[len('object_ratelimit_'):]
                amount, ttl = conf[conf_key].split(':')
                self.conf_limits.append((match, int(amount), int(ttl)))
            if conf_key.startswith('object_ratelimit-exempt_header_'):
                header = conf_key[len('object_ratelimit-exempt_header_'):]
                values = [v if v != 'None' else None for v in conf[conf_key].split(':')]
                self.exempt_header[header] = values
        if 'object_ratelimit' in conf:
            match = ''
            amount, ttl = conf['object_ratelimit'].split(':')
            self.conf_limits.append((match, int(amount), int(ttl)))

    def handle_ratelimit(self, env, start_response, req):
        '''
        Returns None if limit not exceeded, a 498 otherwise.
        '''
        # process header exemptions
        for (header, values) in self.exempt_header.items():
            value = req.headers.get(header)
            if value in values:
                self.logger.increment("exempt_header.%s" % header)
                return self.app(env, start_response)
        # parse request
        try:
            version, account, container, obj = split_path(req.path, 1, 4, True)
        except ValueError:
            self.logger.increment("req_bad")
            return self.app(env, start_response)
        # the request is not for an object, but for a container,account, ...
        if obj is None:
            self.logger.increment("not_an_object")
            return self.app(env, start_response)
        limit = None
        for conf_limit in self.conf_limits:
            match, amount, ttl = conf_limit
            if match in req.path_qs:
                limit = conf_limit
                break
        if limit is None:
            self.logger.increment("not_applicable")
            return self.app(env, start_response)
        # uniquely identify the object:
        key = "objectratelimit_%s/%s/%s" % (account, container, obj)

        # notes:
        # * not atomic. can be racey
        # (if key doesn't exist, memcache lib will add it in sep. request)
        # for our use case, this is acceptable, it just loosens the limit a bit
        # * if a user has a bunch of connection drops and retries,
        #   they could reach their limit.
        #   options:
        #   1 incrementing counter at the end of successful transfer
        #   (not necessarily accurate due to load balancers, proxies etc),
        #   but would leave a big race condition
        #   2 incrementing a counter in the beginning and decrementing on
        #   error could be gamed (range requests, cutting connection, etc)
        #   3 imposing a (temporary) rate limit in that case is not
        #   unreasonable, so I'll just leave it like this
        try:
            reqs = self.memcache_client.incr(key, timeout=ttl)
        except MemcacheConnectionError:
            self.logger.increment("memcache_error")
            return self.app(env, start_response)
        if reqs > amount:
            self.logger.increment("limit_reached")
            self.logger.warning(_(
                'Rate limit of %i reached: %i requests for %s (TTL %i)'),
                amount, reqs, obj, ttl)
            return Response(status='498 Rate Limit reached',
                            body='Rate limit reached',
                            request=req)(env, start_response)
        self.logger.increment("limit_not_reached")
        return self.app(env, start_response)

    def __call__(self, env, start_response):
        """
        WSGI entry point.
        Wraps env in webob.Request object and passes it down.

        :param env: WSGI environment dictionary
        :param start_response: WSGI callable
        """
        req = Request(env)
        if self.memcache_client is None:
            self.memcache_client = cache_from_env(env)
        if not self.memcache_client:
            self.logger.warning(
                _('Warning: Cannot ratelimit without a memcached client'))
            self.logger.increment("memcache_disabled")
            return self.app(env, start_response)
        return self.handle_ratelimit(env, start_response, req)


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def limit_filter(app):
        return ObjectRateLimitMiddleware(app, conf)
    return limit_filter

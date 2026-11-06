using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Sample;

/// <summary>
/// 서버 세션 저장소. 쿠키에는 세션 키만 담고 로그인 정보(ticket)는 서버에 둔다.
/// 그래야 back-channel 로그아웃·퇴사 웹훅이 남의 세션을 끝낼 수 있다.
/// 예제라 메모리에 두지만 서버가 여러 대면 Redis·DB(IDistributedCache)에 둔다.
/// </summary>
public sealed class SessionStore : ITicketStore
{
    private readonly ConcurrentDictionary<string, AuthenticationTicket> _tickets = new();

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Guid.NewGuid().ToString("N");
        _tickets[key] = ticket;
        return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        _tickets[key] = ticket;
        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key) =>
        Task.FromResult(_tickets.TryGetValue(key, out var t) ? t : null);

    public Task RemoveAsync(string key)
    {
        _tickets.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    /// <summary>sid 가 있으면 그 로그인 세션만, 없으면 sub 의 세션을 모두 끝낸다. 끝낸 수를 돌려준다</summary>
    public int End(string? sub, string? sid)
    {
        var keys = _tickets
            .Where(kv => sid != null
                ? kv.Value.Principal.FindFirst("sid")?.Value == sid
                : kv.Value.Principal.FindFirst("sub")?.Value == sub)
            .Select(kv => kv.Key)
            .ToList();
        keys.ForEach(k => _tickets.TryRemove(k, out _));
        return keys.Count;
    }
}

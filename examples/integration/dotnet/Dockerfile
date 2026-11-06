FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Sample.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
# 컨테이너 안의 localhost:8080 을 호스트의 IAM 으로 넘긴다 (토큰 iss 가 http://localhost:8080 이라서)
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_URLS=http://0.0.0.0:4108
ENTRYPOINT ["sh", "-c", "socat TCP-LISTEN:8080,fork,reuseaddr TCP:host.docker.internal:8080 & exec dotnet Sample.dll"]

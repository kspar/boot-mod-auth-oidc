package ee.xvf.bootmodauthoidc

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@SpringBootApplication
class App

fun main(args: Array<String>) {
    runApplication<App>(*args)
}

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
class SecurityConfig : WebSecurityConfigurerAdapter() {
    override fun configure(http: HttpSecurity) {
        http.authorizeRequests().anyRequest().authenticated()
        http.addFilterAfter(PreAuthHeaderFilter(), RequestHeaderAuthenticationFilter::class.java)

        http.exceptionHandling()
                .accessDeniedHandler(EasyAccessDeniedHandler())
                .authenticationEntryPoint { _, response, _ ->
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED)
                }

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        http.csrf().disable()
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(EasyAuthProvider())
    }
}

class PreAuthHeaderFilter : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val email = getRequiredHeader("oidc_claim_email", request)
        val givenName = getRequiredHeader("oidc_claim_given_name", request)
        val familyName = getRequiredHeader("oidc_claim_family_name", request)

        val roles = mapHeaderToRoles(getRequiredHeader("oidc_claim_easy_role", request))

        val user = EasyUser(email, givenName, familyName, roles)
        SecurityContextHolder.getContext().authentication = user

        filterChain.doFilter(request, response)
    }

    private fun getRequiredHeader(headerName: String, request: HttpServletRequest): String {
        val headerValue: String? = request.getHeader(headerName)
        if (headerValue.isNullOrBlank()) {
            throw RuntimeException("$headerName header not found")
        } else {
            return headerValue
        }
    }

    private fun mapHeaderToRoles(rolesHeader: String): Set<EasyGrantedAuthority> =
            rolesHeader.split(",")
                    .map {
                        when (it) {
                            "student" -> EasyGrantedAuthority(EasyRole.STUDENT)
                            "teacher" -> EasyGrantedAuthority(EasyRole.TEACHER)
                            else -> throw RuntimeException("Unmapped role $it")
                        }
                    }
                    .toSet()

}

class EasyUser(val email: String, val givenName: String, val familyName: String, val roles: Set<EasyGrantedAuthority>) :
        AbstractAuthenticationToken(roles) {

    // We have no credentials
    override fun getCredentials(): Any? = null

    override fun getPrincipal(): Any = email
}


class EasyGrantedAuthority(private val role: EasyRole) : GrantedAuthority {
    override fun getAuthority(): String = role.roleWithPrefix
}

enum class EasyRole(val roleWithPrefix: String) {
    STUDENT("ROLE_STUDENT"),
    TEACHER("ROLE_TEACHER")
}


@Component
class EasyAuthProvider : AuthenticationProvider {
    override fun authenticate(authentication: Authentication?): Authentication? {
        authentication?.isAuthenticated = true
        return authentication
    }

    override fun supports(authentication: Class<*>?): Boolean =
            EasyUser::class.java.isAssignableFrom(authentication)

}


class EasyAccessDeniedHandler : AccessDeniedHandler {
    override fun handle(request: HttpServletRequest?, response: HttpServletResponse, accessDeniedException: AccessDeniedException?) {
        response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
}

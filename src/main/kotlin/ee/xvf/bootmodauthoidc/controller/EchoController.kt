package ee.xvf.bootmodauthoidc.controller

import org.springframework.security.access.annotation.Secured
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.util.*
import javax.servlet.http.HttpServletRequest

@RestController
class EchoController {

    @GetMapping("/teacher")
    @Secured("ROLE_TEACHER")
    fun echoTeacher(req: HttpServletRequest): String {

        return req.headerNames.toList().union(Arrays.asList("TEACHER"))
                .joinToString("<br/>") { "$it : ${req.getHeader(it)}" }
    }

    @GetMapping("/student")
    @Secured("ROLE_STUDENT")
    fun echoStudent(req: HttpServletRequest, auth: Authentication?): String {

        return req.headerNames.toList().union(Arrays.asList("STUDENT"))
                .joinToString("<br/>") { "$it : ${req.getHeader(it)}" }
    }

    @GetMapping("/noauth")
    fun echoNoAuth(req: HttpServletRequest, auth: Authentication?): String {

        return req.headerNames.toList().union(Arrays.asList("NOAUTH"))
                .joinToString("<br/>") { "$it : ${req.getHeader(it)}" }
    }

}
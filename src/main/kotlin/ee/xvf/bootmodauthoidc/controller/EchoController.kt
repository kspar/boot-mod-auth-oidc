package ee.xvf.bootmodauthoidc.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpServletRequest

@RestController
class EchoController {

    @GetMapping("/")
    fun echo(req: HttpServletRequest): String {

        return req.headerNames.toList()
                .joinToString("<br/>") { "$it : ${req.getHeader(it)}" }
    }

}
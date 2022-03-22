package org.scriptonbasestar.auth.oauth2.filter

import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.slf4j.LoggerFactory

class GlobalFilterChain(
    private val filterChain: LinkedHashSet<SBFilter>,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(GlobalFilterChain::class.java)
    }

    fun process(contextIn: CallContextIn) {
        if (logger.isDebugEnabled) {
            logger.debug("global filter >>>>>>>>>>")
            logger.debug("global filter {}", contextIn)
        }
        filterChain.forEach {
            it.call(contextIn)
        }
        if (logger.isDebugEnabled) {
            logger.debug("global filter <<<<<<<<<<")
        }
    }
}

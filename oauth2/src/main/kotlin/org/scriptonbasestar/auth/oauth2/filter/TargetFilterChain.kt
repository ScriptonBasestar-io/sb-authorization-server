package org.scriptonbasestar.auth.oauth2.filter

import org.scriptonbasestar.auth.oauth2.context.CallContextIn
import org.slf4j.LoggerFactory

class TargetFilterChain(
    private val filterChain: LinkedHashSet<SBFilter>,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(TargetFilterChain::class.java)
    }

    fun process(contextIn: CallContextIn) {
        if(logger.isDebugEnabled){
            logger.debug("target filter >>>>>>>>>>")
            logger.debug("target filter {}", contextIn)
        }
        filterChain.forEach {
            it.call(contextIn)
        }
        if (logger.isDebugEnabled) {
            logger.debug("target filter <<<<<<<<<<")
        }
    }
}

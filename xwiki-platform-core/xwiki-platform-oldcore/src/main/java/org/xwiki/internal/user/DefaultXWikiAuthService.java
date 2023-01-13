/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.internal.user;

import java.security.Principal;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.security.authentication.AuthenticationConfiguration;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiAuthService;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;

/**
 * The default implementation of {@link XWikiAuthService}, in charge of proxying to the right authentication service
 * based on the configuration.
 * 
 * @version $Id$
 * @since 15.0RC1
 */
@Component
@Singleton
public class DefaultXWikiAuthService implements XWikiAuthService
{
    @Inject
    private AuthenticationConfiguration configuration;

    @Inject
    @Named(XWikiAuthServiceImpl.HINT)
    private XWikiAuthService standardAuthenticator;

    @Inject
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    private Logger logger;

    private XWikiAuthService getXWikiAuthService() throws XWikiException
    {
        String authHint = this.configuration.getAuthenticationService();

        if (authHint != null) {
            ComponentManager componentManager = this.componentManagerProvider.get();
            if (componentManager.hasComponent(XWikiAuthService.class, authHint)) {
                try {
                    return componentManager.getInstance(XWikiAuthService.class, authHint);
                } catch (ComponentLookupException e) {
                    throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                        authHint, e);
                }
            } else {
                this.logger.warn("No authentication service could be found for identifier [{}]. "
                    + "Fallbacking on the standard one.", authHint);
            }
        }

        return this.standardAuthenticator;
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        return getXWikiAuthService().checkAuth(context);
    }

    @Override
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context)
        throws XWikiException
    {
        return getXWikiAuthService().checkAuth(username, password, rememberme, context);
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        getXWikiAuthService().showLogin(context);
    }

    @Override
    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException
    {
        return getXWikiAuthService().authenticate(username, password, context);
    }
}

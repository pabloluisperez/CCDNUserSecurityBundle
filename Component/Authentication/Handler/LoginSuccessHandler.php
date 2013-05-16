<?php

/*
 * This file is part of the CCDNUser SecurityBundle
 *
 * (c) CCDN (c) CodeConsortium <http://www.codeconsortium.com/>
 *
 * Available on github <http://www.github.com/codeconsortium/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace CCDNUser\SecurityBundle\Component\Authentication\Handler;

use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Bundle\FrameworkBundle\Routing\Router;

use CCDNUser\SecurityBundle\Component\Authentication\Tracker\LoginFailureTracker;

/**
 *
 * @author Reece Fowell <reece@codeconsortium.com>
 * @version 1.0
 */
class LoginSuccessHandler implements AuthenticationSuccessHandlerInterface
{
    /**
     *
     * @access protected
	 * @var \Symfony\Bundle\FrameworkBundle\Routing\Router $router
     */
    protected $router;
	
    /**
     *
     * @access protected
	 * @var \CCDNUser\SecurityBundle\Component\Authentication\Tracker\LoginFailureTracker $loginFailureTracker
     */
    protected $loginFailureTracker;
	
    /**
     *
     * @access protected
	 * @var bool $enableShield
     */
    protected $enableShield;
	
    /**
     *
     * @access protected
	 * @var string $loginRoute
     */
    protected $loginRoute;
	
    /**
     *
     * @access protected
	 * @var array $loginRouteParams
     */
    protected $loginRouteParams;
	
    /**
     *
     * @access public
     * @param \Symfony\Bundle\FrameworkBundle\Routing\Router $router
	 * @param \CCDNUser\SecurityBundle\Component\Authentication\Tracker\LoginFailureTracker $loginFailureTracker
	 * @param bool $enableShield
	 * @param string $loginRoute
	 * @param array $loginRouteParams
     */
    public function __construct(Router $router, LoginFailureTracker $loginFailureTracker, $enableShield, $loginRoute, $loginRouteParams)
    {
		$this->router = $router;
		$this->loginFailureTracker = $loginFailureTracker;
		$this->enableShield = $enableShield;
		$this->loginRoute = $loginRoute;
		$this->loginRouteParams = $loginRouteParams;
    }

    /**
     *
     * @access public
     * @param \Symfony\Component\HttpFoundation\Request $request
	 * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\Symfony\Component\HttpFoundation\Response
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $session = $request->getSession();
        $ipAddress = $request->getClientIp();
        $attempts = $this->loginFailureTracker->getAttempts($session, $ipAddress);

        if(count($attempts)>=3){
            $response = new Response(
  				    json_encode(
  					     array(
  						      'status' => 'failed',
  						      'errors' => array('Espere 10 minutos para volver a intentar loguear.')
  					     )
  				    )
  			   );
         			
          $response->headers->set('Content-Type', 'application/json');
			    return $response;
        }

        if ($session->has('referer')) {
            if ($session->get('referer') !== null
            && $session->get('referer') !== '')
            {
                $response = new RedirectResponse($session->get('referer'));
            } else {
                $response = new RedirectResponse($request->getBasePath() . '/');
            }
        } else {
            // if no referer then go to homepage
            $response = new RedirectResponse($request->getBasePath() . '/');
        }

        if ($request->isXmlHttpRequest() || $request->request->get('_format') === 'json') {
            $response = new Response(json_encode(array('status' => 'success')));
            $response->headers->set('Content-Type', 'application/json');
        }

        return $response;
    }
}
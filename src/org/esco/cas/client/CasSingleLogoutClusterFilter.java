package org.esco.cas.client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.util.CommonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * CasSingleLogoutClusterFilter broadcast SLO request to each node of the cluster.
 * Send request with multi threading.
 * 
 * http://pl.digipedia.org/usenet/thread/13576/1221/
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class CasSingleLogoutClusterFilter implements Filter {

	/** Logger. */
	private static final Logger LOG = LoggerFactory.getLogger(CasSingleLogoutClusterFilter.class);

	/** Header included in a forwarded SLO request. */
	private static final String X_FORWARDED_LOGOUT_HEADER = "X-Forwarded-SLO-Request";

	/** HTTP Client read timeout. */
	private static int readTimeout = 30000;

	/** HTTP Client connection timeout. */
	private static int connectionTimeout = 30000;

	/** CAS HTTP param for logout request. */
	private static final String CAS_LOGOUT_REQUEST_HTTP_PARAM = "logoutRequest";

	/** Parameter to configure the server hostname. */
	private static final String CLIENT_HOSTNAME_PARAMETER = "clientHostName";

	/** Parameter to configure the peers URLs. */
	private static final String PEERS_PARAMETER = "peersUrls";

	/** Peers config usage. */
	private static final String PEERS_USAGE = String.format(
			"%1$s filter parameter need to be configured correctly with separated comas \"protocol://hostname:port\".",
			CasSingleLogoutClusterFilter.PEERS_PARAMETER);

	/** Regexp to obtain Session Index contained in Logout Request message. */
	private static final String LR_SI_REGEXP = ".*<samlp:SessionIndex>([^<]*).*";

	/** Pattern to obtain Session Index contained in Logout Request message. */
	private static final Pattern LR_SI_PATTERN = Pattern.compile(CasSingleLogoutClusterFilter.LR_SI_REGEXP);

	/** Configured peers in the cluster. */
	private final Collection <Peer> peers = new HashSet<Peer>(32);

	/** Hostname of this client. */
	private String clientHostName;

	/** Executor service for message sending. */
	private ExecutorService EXECUTOR_SERVICE = Executors.newFixedThreadPool(100);

	@Override
	public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
			throws IOException, ServletException {
		CasSingleLogoutClusterFilter.LOG.trace("Filtering with request: [{}] ; method: [{}]", request);

		if (!this.peers.isEmpty() && (request instanceof HttpServletRequest)) {
			final HttpServletRequest httpRequest = (HttpServletRequest) request;
			CasSingleLogoutClusterFilter.LOG.trace("Filtering with HTTP method: [{}] ; parameters: [{}] ", httpRequest.getMethod(), httpRequest.getParameterMap().toString());

			if ("POST".equals(httpRequest.getMethod())) {

				//This a CAS client method I use
				final String logoutRequest = CommonUtils.safeGetParameter(httpRequest, CasSingleLogoutClusterFilter.CAS_LOGOUT_REQUEST_HTTP_PARAM);
				//final String logoutRequest = httpRequest.getParameter(CasSingleLogoutClusterFilter.CAS_LOGOUT_REQUEST_HTTP_PARAM);
				CasSingleLogoutClusterFilter.LOG.debug("{}: [{}]", CasSingleLogoutClusterFilter.CAS_LOGOUT_REQUEST_HTTP_PARAM, logoutRequest);

				// Set a flag so an application getting a rebroadcast doesn't rebroadcast it. don't want a packet storm
				final String rebroadcast = httpRequest.getHeader(CasSingleLogoutClusterFilter.X_FORWARDED_LOGOUT_HEADER);
				CasSingleLogoutClusterFilter.LOG.debug("rebroadcast: [{}]", rebroadcast);

				if (StringUtils.hasText(logoutRequest) && (rebroadcast == null)) {
					try {
						final String path = httpRequest.getServletPath();
						final String context = httpRequest.getContextPath();
						final String protocol = httpRequest.getScheme();

						CasSingleLogoutClusterFilter.LOG.debug("Got a single logout request ; protocol: [{}] ; context: [{}] ; path: [{}].",
								new Object[]{protocol, context, path});

						// Set up the http client connection
						CasSingleLogoutClusterFilter.LOG.debug("Attempting to rebroadcast");

						// Peers are set in the init() method
						for (Peer peer : this.peers) {
							if (!peer.getHostName().equals(this.clientHostName)) {
								// don't rebroadcast to your self!
								CasSingleLogoutClusterFilter.LOG.debug("Processing peer: [{}]", peer);

								// set rebroadcast=false so peers don't rebroacast. Only first recipient reboradcasts
								this.sendLogoutRequestToPeer(peer, context + path, logoutRequest, true);
							}
						}
					} catch (Exception e) {
						CasSingleLogoutClusterFilter.LOG.error("Error while broadcasting logout request !", e);
					}
				}
			}
		}

		chain.doFilter(request, response);
	}

	@Override
	public void init(final FilterConfig config) throws ServletException {
		// Get local hostName on initialization
		this.clientHostName = config.getInitParameter(CasSingleLogoutClusterFilter.CLIENT_HOSTNAME_PARAMETER);

		if (!StringUtils.hasText(this.clientHostName)) {
			try {

				final InetAddress localMachine = InetAddress.getLocalHost();
				this.clientHostName = localMachine.getHostName();
				CasSingleLogoutClusterFilter.LOG.info("Detected Hostname for local machine: [{}]", this.clientHostName);
			} catch (UnknownHostException e) {
				final String errorMsg = String.format(
						"Error while detecting IP Address of server. You need to configure the filter parameter: [%1$s]"
						, CasSingleLogoutClusterFilter.CLIENT_HOSTNAME_PARAMETER);
				CasSingleLogoutClusterFilter.LOG.error(errorMsg, e);
			}
		}

		// Get comma delimited list of peer dns names from a filter config
		final String peerList = config.getInitParameter(CasSingleLogoutClusterFilter.PEERS_PARAMETER);
		if (!StringUtils.hasText(peerList)) {
			CasSingleLogoutClusterFilter.LOG.warn("No peers URL configured the CasSingleLogoutClusterFilter will not works !");
		}

		String[] peersDescription = peerList.split(",");
		for (String peerDescription : peersDescription) {
			try {
				this.peers.add(new Peer(peerDescription));
			} catch (MalformedURLException e) {
				// We don't block the webapp initializiation. Just log an error.
				CasSingleLogoutClusterFilter.LOG.error("Malformed peer URL [{}] among CasSingleLogoutClusterFilter peers !", peerDescription);
				//throw new ServletException("Malformed URL among CasSingleLogoutClusterFilter peers !", e);
			}
		}

		if (!StringUtils.hasText(this.clientHostName)) {
			CasSingleLogoutClusterFilter.LOG.warn("No client hostname configured the CasSingleLogoutClusterFilter may not works !");
		}

		if (CollectionUtils.isEmpty(this.peers)) {
			CasSingleLogoutClusterFilter.LOG.warn("No valid peers URL configured the CasSingleLogoutClusterFilter will not works !");
		}

		CasSingleLogoutClusterFilter.LOG.info("Client hostname: [{}]", this.clientHostName);
		CasSingleLogoutClusterFilter.LOG.info("SLO cluster peers: [{}]", peerList.toString());
	}

	/**
	 * Add a message sender in the queue.
	 * 
	 * @param peer
	 * @param url
	 * @param message
	 * @param async
	 * @return
	 */
	public boolean sendLogoutRequestToPeer(final Peer peer, final String url, final String message, final boolean async) {
		final Future<Boolean> result = this.EXECUTOR_SERVICE.submit(new MessageSender(peer, url, message));
		if (async) {
			return true;
		}
		try {
			return result.get();
		} catch (final Exception e) {
			return false;
		}
	}

	/**
	 * Message sender.
	 * 
	 * @author GIP RECIA 2013 - Maxime BOSSARD.
	 *
	 */
	private final class MessageSender implements Callable<Boolean> {

		private static final String INFO_MESSAGE = "[%1$s] to [%2$s://%3$s:%4$d%5$s]";

		private Peer peer;
		private String url;
		private String message;

		protected MessageSender(final Peer peer, final String url, final String message) {
			super();
			this.peer = peer;
			this.url = url;
			this.message = message;
		}

		@Override
		public Boolean call() throws Exception {
			return this.sendLogoutRequestToPeer(this.peer, this.url, this.message);
		}

		/**
		 * Send a logout request to a peer.
		 * 
		 * Method to send logout request to peers, I think I stole it from the CAS server code?
		 * 
		 * @param host hostname of the peer
		 * @param port port number to contact the peer (80, 443, ...)
		 * @param url path where to send the SLO request
		 * @param message the content of the SLO.
		 * 
		 * @return true if the SLO was successfuly sent
		 */
		protected boolean sendLogoutRequestToPeer(final Peer peer,
				final String url, final String message) throws IOException {

			boolean test = false;

			final String peerProtocol = peer.getProtocol();
			final String peerHostname = peer.getHostName();
			final Integer peerPort = peer.getPort();

			// Info message contain Session Index if we can find it
			// Otherwise we put all the logout request message.
			final Matcher m = CasSingleLogoutClusterFilter.LR_SI_PATTERN.matcher(message);
			final String info;
			if (m.find()) {
				info = m.group(1);
			} else {
				info = message;
			}
			final String infoMsg = String.format(MessageSender.INFO_MESSAGE,
					info, peerProtocol, peerHostname, peerPort, url);

			HttpURLConnection connection = null;
			BufferedReader in = null;
			try {
				CasSingleLogoutClusterFilter.LOG.debug("Attempting to send logout request {}", infoMsg);

				final URL tempUrl = new URL(peerProtocol, peerHostname, peerPort, url);
				final StringBuilder urlWithInfoSb = new StringBuilder(url.length() + 128);
				urlWithInfoSb.append(url);
				if (tempUrl.getQuery() == null) {
					urlWithInfoSb.append("?clusterSloInfo=");
				} else {
					urlWithInfoSb.append("&clusterSloInfo=");
				}
				urlWithInfoSb.append(infoMsg);
				//final String urlWithInfo = URLEncoder.encode(urlWithInfoSb.toString(), "UTF-8");
				final URL logoutUrl = new URL(peerProtocol, peerHostname, peerPort, urlWithInfoSb.toString());

				CasSingleLogoutClusterFilter.LOG.debug("logout URL: [{}]", logoutUrl.toString());

				final String output = "logoutRequest=" + URLEncoder.encode(message, "UTF-8");
				connection = (HttpURLConnection) logoutUrl.openConnection();
				connection.setDoInput(true);
				connection.setDoOutput(true);
				connection.setRequestMethod("POST");
				connection.setReadTimeout(CasSingleLogoutClusterFilter.readTimeout);
				connection.setConnectTimeout(CasSingleLogoutClusterFilter.connectionTimeout);
				connection.setRequestProperty(CasSingleLogoutClusterFilter.X_FORWARDED_LOGOUT_HEADER, "true");
				connection.setRequestProperty("Content-Length", "" + Integer.toString(output.getBytes().length));
				connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
				final DataOutputStream printout = new DataOutputStream(connection.getOutputStream());
				printout.writeBytes(output);
				printout.flush();
				printout.close();
				in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
				while (in.readLine() != null) {
					// nothing to do
				}
				CasSingleLogoutClusterFilter.LOG.info(
						"Finished sending logout request to [{}] with response [{} {}]",
						new Object[]{peer, connection.getResponseCode(), connection.getResponseMessage()});

				test = true;
			} catch (final SocketTimeoutException e) {
				CasSingleLogoutClusterFilter.LOG.error("Socket Timeout Detected while attempting to rebroadcast logout request {}", infoMsg);
			} catch (final Exception e) {
				final String errorMsg = String.format("An exception occured while attempting to rebroadcast logout request %1$s", infoMsg);
				CasSingleLogoutClusterFilter.LOG.error(errorMsg, e);
			} finally {
				if (in != null) {
					in.close();
				}
				if (connection != null) {
					connection.disconnect();
				}
			}

			return test;
		}

	}

	private class Peer {

		/** Peer protocol to use. */
		private String protocol;

		/** Peer hostName. */
		private String hostName;

		/** Peer port number. */
		private Integer port;

		/**
		 * Build peer from a description like "hostname:port".
		 * 
		 * @param peerDescription
		 * @throws MalformedURLException
		 */
		private Peer(final String peerDescription) throws MalformedURLException {
			super();

			if (StringUtils.hasText(peerDescription)) {

				final URL url = new URL(peerDescription);

				this.protocol = url.getProtocol();
				this.hostName = url.getHost();
				this.port = url.getPort();
			}

			if (!StringUtils.hasText(this.protocol) || !StringUtils.hasText(this.hostName)
					|| (this.port == -1)) {
				CasSingleLogoutClusterFilter.LOG.warn(CasSingleLogoutClusterFilter.PEERS_USAGE);
			}
		}

		@Override
		public String toString() {
			return String.format("%1$s://%2$s:%3$d", this.protocol, this.hostName, this.port);
		}

		public String getProtocol() {
			return this.protocol;
		}

		public String getHostName() {
			return this.hostName;
		}

		public Integer getPort() {
			return this.port;
		}

	}

	@Override
	public void destroy() {
		this.peers.clear();
		this.EXECUTOR_SERVICE.shutdownNow();
	}
}

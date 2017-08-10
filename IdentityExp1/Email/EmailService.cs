using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging; // ILogger
using Microsoft.Extensions.Options; // IOptions
//using Microsoft.Extensions.Configuration;

using MailKit.Net.Smtp;
using MailKit;
using MimeKit;

using Newtonsoft.Json;

using System.Threading;
using System.Collections.Concurrent;



namespace NZ01
{

    public interface IEmailService
    {
        bool Enqueue(EmailContext emailContext);
        void Clear();
        void Stop();

        // Properties
        bool WarnFlag { get; set; }
        bool ErrorFlag { get; set; }
        int ThresholdLevelWarn { get; set; }
        int ThresholdLevelError { get; set; }
    }

    /// <summary>
    /// Class to encapsulate a service that will send emails.
    /// </summary>
    /// <remarks>
    /// This requires an entry in the config for EmailOptions.
    /// WARNING: Do not use _logger.LogWarning() or _logger.LogError(), 
    /// as this may cause an infinite loop.  
    /// Consider an error that occurs in email, and this is logged,
    /// and the logger is configured to email errors, so this is 
    /// added to the email queue, and the email errors, and we loop infinitely.  
    /// To combat this, the log message text can contain ERROR or WARNING, so 
    /// that such entries can still quickly be found in the logs.
    /// </remarks>
    public class EmailService : IEmailService
    {
        public static readonly string EMAIL_PASSWORD = "CORE_EMAIL_PASSWORD"; // Environment variable key

        private readonly ILogger _logger; // Do not use Logger.LogError() or Logger.LogWarning() within this class, else, BOOM! Infinite Loop.
        private readonly EmailOptions _emailOptions;

        private ConcurrentQueue<EmailContext> _queue = new ConcurrentQueue<EmailContext>();

        private Thread _thread;
        private readonly string _threadName = "EmailService";
        private bool _running = true;
        private AutoResetEvent _eventThreadExit = new AutoResetEvent(false);
        private AutoResetEvent _eventThreadAction = new AutoResetEvent(false);
        private int _waitTimeout = 1000; // 1 second - Effects responsiveness to shutdown
        


        // Properties
        public int ThresholdLevelWarn { get; set; } = 100; // Warn but accept messages if this number of messages is on the queue
        public int ThresholdLevelError { get; set; } = 1000; // Error and reject messages if this number of messages is on the queue

        public bool WarnFlag { get; set; } = false;
        public bool ErrorFlag { get; set; } = false;




        public EmailService(
            ILogger<EmailService> logger,
            IOptions<EmailOptions> options)
        {
            string prefix = nameof(EmailService) + Constants.FNSUFFIX + " [CTOR] ";

            _logger = logger;
            _emailOptions = options.Value;

            _thread = new Thread(new ThreadStart(runThread));
            _thread.Name = _threadName;
            _thread.IsBackground = true; // Thread will be stopped like a pool thread if app is closed.

            _logger.LogInformation(prefix + $"About to start {_threadName} Thread...");
            _thread.Start();
            _logger.LogInformation(prefix + $"{_threadName} Thread started...");

            _logger.LogDebug(prefix + "Entering/Exiting");
        }


        /// <summary>
        /// Add an email context to the queue to send.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public bool Enqueue(EmailContext context)
        {
            int countQueued = _queue.Count;
            if (checkCapacity(countQueued))
            {
                _queue.Enqueue(context);
                _eventThreadAction.Set();
                return true;
            }
            else
                return false;
        }

        /// <summary>
        /// Clear the queue if something is wrong
        /// </summary>
        public void Clear()
        {
            string prefix = nameof(Clear) + Constants.FNSUFFIX;

            _queue = new ConcurrentQueue<EmailContext>(); // Quickest way to clear the queue is to swap in a new one. Ref: https://social.msdn.microsoft.com/Forums/en-US/accf4254-ee81-4059-9251-619bc6bbeadf/clear-a-concurrentqueue?forum=rx

            _logger.LogInformation(prefix + "WARNING: The contents of the email queue have been cleared.");
        }

        /// <summary>
        /// Stop processing the queue as a prelude to shutting down.
        /// </summary>
        public void Stop()
        {
            string prefix = nameof(Stop) + Constants.FNSUFFIX;

            _running = false; // Stops the thread wait infinite loop

            if (_eventThreadExit.WaitOne())
                _logger.LogInformation(prefix + $"Graceful Shutdown - {_threadName} Thread has signalled that it has stopped.");
            else
                _logger.LogInformation(prefix + $"Bad Shutdown - {_threadName} Thread did not signal that it had stopped.");
        }



        private void runThread()
        {
            while (_running)
            {
                if (_eventThreadAction.WaitOne(_waitTimeout))
                    consumeQueue(); // Signal Received                
            }

            // Signal that the thread has exited.
            _eventThreadExit.Set();
        }


        /// <summary>
        /// Check all required settings have value
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        private bool validSettings(string password)
        {
            string prefix = nameof(validSettings) + Constants.FNSUFFIX;

            List<string> errors = new List<string>();

            if (string.IsNullOrWhiteSpace(password)) errors.Add($"No password set in env var {EMAIL_PASSWORD}");
            if (string.IsNullOrWhiteSpace(_emailOptions.Host)) errors.Add("Email Host missing");
            if (_emailOptions.Port <= 0) errors.Add($"Port is invalid:[{_emailOptions.Port}]");
            if (string.IsNullOrWhiteSpace(_emailOptions.Username)) errors.Add("Email Username missing");

            string sErrors = string.Join("; ", errors);
            int iCountErrors = errors.Count;

            if (errors.Count > 0)
            {
                _logger.LogInformation(prefix + $"ERROR: Email Options are not configured correctly; Errors:[{sErrors}]");
                return false;
            }

            return true;
        }

        private void consumeQueue()
        {
            string prefix = nameof(consumeQueue) + Constants.FNSUFFIX;

            if (!validSettings(_emailOptions.Password))
                return;

            // Make one connection to email server for all emails to send
            using (var client = new SmtpClient())
            {
                try
                {
                    client.ServerCertificateValidationCallback = ((s, c, h, e) => true);

                    client.Connect(
                        _emailOptions.Host,
                        _emailOptions.Port,
                        _emailOptions.EnableSsl);

                    client.AuthenticationMechanisms.Remove("XOAUTH2");

                    client.Authenticate(_emailOptions.Username, _emailOptions.Password);
                }
                catch (Exception ex)
                {
                    _logger.LogInformation(prefix + $"ERROR: Exception during attempt to connect to email server; Exception:[{ex.ToString()}]");
                    return;
                }

                if (!client.IsConnected)
                {
                    _logger.LogInformation(prefix + $"ERROR: Failed to connect to email server;  No exception occurred, but SMTP client is not connected.");
                    client.Disconnect(true);
                    return;
                }

                if (!client.IsAuthenticated)
                {
                    _logger.LogInformation(prefix + $"ERROR: Connection to email server was successful but SMTP client is not authenticated.");
                    client.Disconnect(true);
                    return;
                }

                // Should be connected and authenticated
                EmailContext emailContext = null;
                while (_queue.TryDequeue(out emailContext))
                {
                    processQueuedItem(client, emailContext, _queue.Count);
                }

                client.Disconnect(true);

            } // end of using()

        }

        private ICollection<string> processAddressField(string addressField, string addressFieldDefault, char[] delimiters)
        {
            List<string> addresses = new List<string>();

            if (string.IsNullOrWhiteSpace(addressField))
            {
                if (!string.IsNullOrWhiteSpace(addressFieldDefault))
                    addresses.Add(addressFieldDefault);
            }
            else
            {
                string[] arrAddresses = addressField.Split(delimiters);
                foreach (string addr in arrAddresses)
                {
                    addresses.Add(addr);
                }
            }

            return addresses;
        }

        private void processQueuedItem(SmtpClient client, EmailContext emailContext, int countQueued)
        {
            string prefix = nameof(processQueuedItem) + Constants.FNSUFFIX;

            _logger.LogInformation(prefix + $"About to attempt send for Context:[{JsonConvert.SerializeObject(emailContext)}]");

            char[] delimiters = new char[] { ',', ';', ' ' }; // Permit addresses to be separated by commas, semis or spaces
            List<string> addressesTo = (List<string>)processAddressField(emailContext.To, _emailOptions.To, delimiters);
            List<string> addressesFrom = (List<string>)processAddressField(emailContext.From, _emailOptions.From, delimiters);

            if (addressesTo.Count == 0)
            {
                string error = "The receiver (To) address list is empty.";
                emailContext.Errors.Add(error);
                emailContext.IsCompleted = true;
                _logger.LogInformation(prefix + $"ERROR: Not sending this message; " + error);
                return;
            }

            if (addressesFrom.Count == 0)
            {
                string error = "The send (From) address list is empty.";
                emailContext.Errors.Add(error);
                emailContext.IsCompleted = true;
                _logger.LogInformation(prefix + $"ERROR: Not sending this message; " + error);
                return;
            }


            var message = new MimeMessage();

            foreach (string addressTo in addressesTo)
                message.To.Add(new MailboxAddress(addressTo));

            foreach (string addressFrom in addressesFrom)
                message.From.Add(new MailboxAddress(addressFrom));

            message.Subject = string.IsNullOrWhiteSpace(emailContext.Subject) ? "(no subject)" : emailContext.Subject;

            string body = string.IsNullOrWhiteSpace(emailContext.Body) ? "(no email body text)" : emailContext.Body;
            message.Body = new TextPart("plain") { Text = body };

            try
            {
                client.Send(message);
            }
            catch (Exception ex)
            {
                string error = $"Exception:[{ex.ToString()}].";
                emailContext.Errors.Add(error);
                emailContext.IsCompleted = true;
                _logger.LogInformation(prefix + $"ERROR: Exception during Send() attempt for Context:[{JsonConvert.SerializeObject(emailContext)}]; " + error);
                return;
            }

            emailContext.IsCompleted = true;
            _logger.LogInformation(prefix + $"Send completed for Context:[{JsonConvert.SerializeObject(emailContext)}]");
        }





        ///////////////////////////////////////////////////////////////////////////////////
        // HELPERS
        //

        private bool checkCapacity(int countQueued)
        {
            string prefix = nameof(checkCapacity) + Constants.FNSUFFIX;

            if (countQueued > ThresholdLevelWarn && WarnFlag == false)
            {
                WarnFlag = true;

                string msg = $"WARNING: The {_threadName} message queue has passed {ThresholdLevelWarn} messages.";
                _logger.LogInformation(prefix + msg);
            }

            if (countQueued > ThresholdLevelError)
            {
                if (ErrorFlag == false)
                {
                    ErrorFlag = true;

                    string msg = $"ERROR: The {_threadName} message queue has passed {ThresholdLevelError} messages";
                    _logger.LogInformation(prefix + msg);
                }

                return false; // Do not add this message to queue
            }

            return true; // Queue message
        }
    }
}

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ResultOf;

namespace FileSenderRailway
{
    public class FileSender
    {
        private readonly ICryptographer cryptographer;
        private readonly IRecognizer recognizer;
        private readonly Func<DateTime> now;
        private readonly ISender sender;

        public FileSender(
            ICryptographer cryptographer,
            ISender sender,
            IRecognizer recognizer,
            Func<DateTime> now)
        {
            this.cryptographer = cryptographer;
            this.sender = sender;
            this.recognizer = recognizer;
            this.now = now;
        }

        private Result<Document> PrepareFileToSend(FileContent file, X509Certificate certificate)
        {
            return recognizer.Recognize(file)
                .Then(d => IsValidFormatVersion(d))
                .Then(d => IsValidTimestamp(d))
                .Then(d => d.RewriteContent(cryptographer.Sign(d.Content, certificate)))
                .RefineError("Can't prepare file to send");
        }

        public IEnumerable<FileSendResult> SendFiles(FileContent[] files, X509Certificate certificate)
        {
            foreach (var file in files)
            {
                string errorMessage = null;

                PrepareFileToSend(file, certificate)
                    .Then(d => sender.Send(d))
                    .OnFail(d => errorMessage = d);

                yield return new FileSendResult(file, errorMessage);
            }
        }

        private Result<Document> IsValidFormatVersion(Result<Document> doc)
        {
            var docValue = doc.Value;
            if (!(docValue.Format == "4.0" || docValue.Format == "3.1"))
                return Result.Fail<Document>(
                    $"Invalid format version. Actual format is {docValue.Format}");
            return doc;
        }

        private Result<Document> IsValidTimestamp(Result<Document> doc)
        {
            var docValue = doc.Value;
            var oneMonthBefore = now().AddMonths(-1);
            if (docValue.Created <= oneMonthBefore)
                return Result.Fail<Document>(
                    $"Too old document. Time of creation is {docValue.Created}");
            return doc;
        }
    }
}
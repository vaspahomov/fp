using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using ResultOfTask;

namespace TagsCloudVisualization
{
    public class WordsCloudFiller
    {
        private const float Coefficient = 5;
        private readonly ICloudLayouter cloudLayouter;
        private readonly Font parentFont;

        public WordsCloudFiller(ICloudLayouter cloudLayouter, Font font)
        {
            this.cloudLayouter = cloudLayouter;
            parentFont = font;
        }

        public Result<Dictionary<string, (Rectangle rectangle, Font font)>> GetRectanglesForWordsInCloud(
            Graphics g,
            Dictionary<string, int> words)
        {
            var maxFrequency = words.First().Value;

            var maxFontSize = parentFont.Size;
            var minFontSize = maxFontSize / Coefficient;

            var font = parentFont;

            var rectangles = new Dictionary<string, (Rectangle rectangle, Font font)>();

            foreach (var word in words)
            {
                font = new Font(font.Name,
                    minFontSize + (maxFontSize - minFontSize) * ((float) word.Value / maxFrequency));
                var size = g.MeasureString(word.Key, font);
                var rectangleResult = cloudLayouter.PutNextRectangle(
                    new Size((int) Math.Ceiling(size.Width), (int) Math.Ceiling(size.Height)));
                if (!rectangleResult.IsSuccess)
                    Result.Fail<Rectangle>(rectangleResult.Error);

                rectangles[word.Key] = (rectangleResult.GetValueOrThrow(), font);
            }

            return Result.Ok(rectangles);
        }
    }
}
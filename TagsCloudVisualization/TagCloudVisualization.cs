﻿using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Linq;
using ResultOfTask;

namespace TagsCloudVisualization
{
    public class TagCloudVisualization : ITagCloudVisualization
    {
        private readonly Color backgroundColor;
        private readonly int bitmapHeight;

        private readonly int bitmapWidth;
        private readonly ICloudLayouter cloudLayouter;
        private readonly Color color;
        private readonly Color defaultBackColor = Color.White;
        private readonly Color defaultColor = Color.Black;

        private readonly Font defaultFont = new Font("Times New Roman", 40);

        private readonly Font font;
        private readonly ImageFormat imageFormat;

        public TagCloudVisualization(
            ICloudLayouter cloudLayouter,
            Font font,
            Color color,
            Color backgroundColor,
            ImageFormat imageFormat)
        {
            this.imageFormat = imageFormat;
            this.font = font;
            this.color = color;
            this.backgroundColor = backgroundColor;
            this.cloudLayouter = cloudLayouter;

            bitmapHeight = 1000;
            bitmapWidth = 1000;
        }

        public TagCloudVisualization(
            ICloudLayouter cloudLayouter)
        {
            font = defaultFont;
            color = defaultColor;
            backgroundColor = defaultBackColor;
            this.cloudLayouter = cloudLayouter;

            bitmapHeight = 1000;
            bitmapWidth = 1000;
        }


        public TagCloudVisualization(
            ICloudLayouter cloudLayouter,
            Font font,
            Color color,
            Color backgroundColor,
            Size size)
        {
            this.font = defaultFont;
            this.color = color;
            this.backgroundColor = backgroundColor;
            this.cloudLayouter = cloudLayouter;

            bitmapHeight = size.Height;
            bitmapWidth = size.Width;
        }

        public void SaveRectanglesCloud(
            string bitmapName,
            string directory,
            List<Rectangle> rectangles,
            Point center)
        {
            var bitmap = new Bitmap(bitmapWidth, bitmapHeight);
            var g = Graphics.FromImage(bitmap);
            DrawBackgroundRectangles(g, rectangles, center);
            var path = $"{directory}\\{bitmapName}-{rectangles.Count}.{imageFormat}";

            bitmap.Save(path, ImageFormat.Png);
        }

        //ToDo Вынести определение размера шрифта в метод
        public Result<None> SaveTagCloud(
            string bitmapName,
            string directory,
            Result<Dictionary<string, int>> wordsResult)
        {
            if (!wordsResult.IsSuccess) return Result.Fail(wordsResult.Error);
            var words = wordsResult.GetValueOrThrow();

            var bitmap = new Bitmap(bitmapWidth, bitmapHeight);
            var g = Graphics.FromImage(bitmap);
            //ToDo вынести из этого класса и убрать ICloudLayouter из конструктора
            var resultWordsInCloud = new WordsCloudFiller(cloudLayouter, font)
                .GetRectanglesForWordsInCloud(g, words);

            if (!resultWordsInCloud.IsSuccess)
                return Result.Fail(resultWordsInCloud.Error);
            var wordsInCloud = resultWordsInCloud.GetValueOrThrow();
            foreach (var rectangle in wordsInCloud.Select(x => x.Value.rectangle))
            {
                if (rectangle.Bottom > bitmapHeight) return Result.Fail("Too small image size");
                if (rectangle.Top < 0) return Result.Fail("Too small image size");
                if (rectangle.Right > bitmapWidth) return Result.Fail("Too small image size");
                if (rectangle.Left < 0) return Result.Fail("Too small image size");
            }

            g.FillRectangle(Brushes.White, 0, 0, bitmapWidth, bitmapHeight);


            DrawBackgroundEllipses(g, wordsInCloud.Select(w => w.Value.rectangle));
            DrawWordsOfCloud(g, wordsInCloud);


            return Result.Of(() => bitmap.Save($"{directory}\\{bitmapName}.{imageFormat}", imageFormat));
        }

        private void DrawBackgroundEllipses(
            Graphics g,
            IEnumerable<Rectangle> rectangles)
        {
            var backgroundBrush = new SolidBrush(backgroundColor);
            foreach (var rectangle in rectangles)
                g.FillEllipse(backgroundBrush, rectangle);
        }

        private void DrawBackgroundRectangles(
            Graphics g,
            IEnumerable<Rectangle> rectangles)
        {
            var backgroundBrush = new SolidBrush(backgroundColor);
            foreach (var rectangle in rectangles)
                g.FillRectangle(backgroundBrush, rectangle);
        }

        private void DrawBackgroundRectangles(
            Graphics g,
            IEnumerable<Rectangle> rectangles,
            Point center)
        {
            var maxDist = (int) rectangles
                .Select(x => GetDistanceFromRectangleToPoint(x, center))
                .Max();

            foreach (var rectangle in rectangles)
            {
                var currentColor = GetColorOfRectangle(rectangle, center, maxDist);
                g.DrawRectangle(new Pen(currentColor), rectangle);
            }
        }

        private void DrawWordsOfCloud(
            Graphics g,
            Dictionary<string, (Rectangle rectangle, Font font)> wordsInCloud)
        {
            var num = 0;
            foreach (var pair in wordsInCloud)
            {
                var rectangle = pair.Value.rectangle;
                var word = pair.Key;
                var brush = new SolidBrush(GetColorOfWord(num, wordsInCloud.Count));

                g.DrawString(word, pair.Value.font, brush, rectangle);
                num++;
            }
        }


        private Color GetColorOfRectangle(Rectangle rectangle, Point center, int maxDist)
        {
            var dist = GetDistanceFromRectangleToPoint(rectangle, center);
            var r = (int) (dist / maxDist * color.R);
            var g = (int) (dist / maxDist * color.G);
            var b = (int) (dist / maxDist * color.B);

            return Color.FromArgb(r, g, b);
        }

        private double GetSmooth(double coefficient)
        {
            return Math.Pow(coefficient, 0.4);
        }

        private Color GetColorOfWord(int num, int count)
        {
            var r = (int) (GetSmooth((double) num / count) * color.R);
            var g = (int) (GetSmooth((double) num / count) * color.G);
            var b = (int) (GetSmooth((double) num / count) * color.B);

            return Color.FromArgb(r, g, b);
        }

        private double GetDistanceFromRectangleToPoint(Rectangle rectangle, Point center)
        {
            return Math.Sqrt((GetCenterOfRectangle(rectangle).X - center.X) *
                             (GetCenterOfRectangle(rectangle).X - center.X) +
                             (GetCenterOfRectangle(rectangle).Y - center.Y) *
                             (GetCenterOfRectangle(rectangle).Y - center.Y));
        }

        private Point GetCenterOfRectangle(Rectangle rectangle)
        {
            return new Point(rectangle.X + rectangle.Width / 2, rectangle.Y + rectangle.Height / 2);
        }
    }
}